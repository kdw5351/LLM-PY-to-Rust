#!/usr/bin/env python3
"""모델 호출. 추가 패키지 없이 stdlib urllib로 OpenAI 호환 / Anthropic API를 부른다.
Ollama, vLLM, LM Studio, OpenAI는 openai provider, Claude는 anthropic provider.

모든 호출은 응답의 토큰 수(prompt/completion)와 seed 전송 여부를 읽어 돌려주고,
`UsageLog`가 run 단위 usage.jsonl에 한 줄씩 적는다(제안서 7절 Cost 지표: 토큰·시간).

유료 API는 config.toml에서 enabled=true로 바꾼 모델만 호출한다. 이 파일은 키가 없으면 호출하지 않는다.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Completion:
    text: str
    prompt_tokens: int | None
    completion_tokens: int | None
    seed_sent: int | None          # 요청에 실은 seed (None이면 안 보냄)
    seed_supported: str            # "yes" | "no" | "unknown"
    model_id: str                  # 응답이 알려준 모델 ID(없으면 요청값)
    latency_s: float
    raw_usage: dict = field(default_factory=dict)


class UsageLog:
    """run 디렉터리의 usage.jsonl. 호출마다 한 줄."""

    def __init__(self, run_dir: Path | None):
        self.path = (run_dir / "usage.jsonl") if run_dir else None
        self.totals = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}

    def record(self, comp: Completion, **ctx) -> dict:
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **ctx,
               "model_id": comp.model_id,
               "prompt_tokens": comp.prompt_tokens, "completion_tokens": comp.completion_tokens,
               "seed_sent": comp.seed_sent, "seed_supported": comp.seed_supported,
               "latency_s": round(comp.latency_s, 2)}
        self.totals["calls"] += 1
        self.totals["prompt_tokens"] += comp.prompt_tokens or 0
        self.totals["completion_tokens"] += comp.completion_tokens or 0
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row


def call_model(model_cfg: dict, system: str, user: str, temperature: float,
               seed: int | None = None, timeout: float = 600.0) -> Completion:
    provider = model_cfg["provider"]
    key = os.environ.get(model_cfg.get("api_key_env", ""), "")
    max_tokens = model_cfg.get("max_tokens", 4096)
    t0 = time.time()
    if provider == "openai":
        url = model_cfg["base_url"].rstrip("/") + "/chat/completions"
        body = {"model": model_cfg["model"], "temperature": temperature,
                "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        if seed is not None:
            body["seed"] = seed
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        data = _post(url, headers, body, timeout)
        usage = data.get("usage") or {}
        # OpenAI는 system_fingerprint로 seed 지원을 알린다. Ollama는 seed를 받지만 응답에 표시하지 않는다.
        supported = "yes" if data.get("system_fingerprint") else ("unknown" if seed is not None else "no")
        return Completion(text=data["choices"][0]["message"]["content"],
                          prompt_tokens=usage.get("prompt_tokens"),
                          completion_tokens=usage.get("completion_tokens"),
                          seed_sent=seed, seed_supported=supported,
                          model_id=data.get("model", model_cfg["model"]),
                          latency_s=time.time() - t0, raw_usage=usage)
    if provider == "anthropic":
        if not key:
            raise RuntimeError(f"API key env {model_cfg.get('api_key_env')} is empty; refusing to call a paid API")
        url = "https://api.anthropic.com/v1/messages"
        body = {"model": model_cfg["model"], "max_tokens": max_tokens,
                "temperature": temperature, "system": system,
                "messages": [{"role": "user", "content": user}]}
        headers = {"Content-Type": "application/json", "x-api-key": key,
                   "anthropic-version": "2023-06-01"}
        data = _post(url, headers, body, timeout)
        usage = data.get("usage") or {}
        return Completion(text="".join(b.get("text", "") for b in data["content"]),
                          prompt_tokens=usage.get("input_tokens"),
                          completion_tokens=usage.get("output_tokens"),
                          seed_sent=None, seed_supported="no",   # Anthropic Messages API에는 seed가 없다
                          model_id=data.get("model", model_cfg["model"]),
                          latency_s=time.time() - t0, raw_usage=usage)
    raise ValueError(provider)


def _post(url: str, headers: dict, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {e.code} from {url}: {detail}") from None


def reachable(model_cfg: dict) -> tuple[bool, str]:
    """모델 엔드포인트가 응답하는지 가볍게 확인. 유료 API도 한 번 호출하므로 enabled 모델만 부른다."""
    try:
        c = call_model(model_cfg, "You are a test.", "Reply with the word OK.", 0.0, seed=0, timeout=60)
        return True, c.text.strip()[:40]
    except Exception as e:
        return False, str(e)[:160]
