"""본 실행 모델 호출기 (본실행_준비완료기준 E1~E4).

하나의 call()로 로컬 Qwen(ollama)·Claude·GPT를 부른다. 지금까지는 하위 에이전트와 파일로 주고받았는데,
본 실행은 API 모델을 같은 인터페이스로 부른다. 지킬 것:
  - 유료 모델은 승인 전까지 부르지 않는다. models.json 에서 enabled=true 인 모델만 부른다(기본 로컬만 true).
  - API 키는 환경 변수에서만 읽는다(코드·설정에 넣지 않는다). 없으면 거절.
  - temperature·seed·최대 토큰을 고정해 받고 기록한다.
  - 모든 요청·응답·토큰·해시를 run/_calls.jsonl 에 남긴다(E4). 같은 호출은 캐시로 이어 간다(E3, 결제 중복 방지).
  - 누적 비용이 상한에 닿으면 멈춘다(E2).

호출 단위 캐시 키 = sha256(model, messages, temperature, seed, max_tokens). 결정적(temperature 0)이 아니어도
같은 키면 저장된 응답을 쓴다(끊겼다 이어 갈 때 이미 한 호출을 다시 결제하지 않으려는 것이다).

usage(코드):
  mc = ModelClient(run_dir)
  text, meta = mc.call("qwen2.5-coder:14b", messages, temperature=0.0, seed=1, max_tokens=8192)
"""
import hashlib
import json
import os
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REGISTRY = HERE / "models.json"
_LOCK = threading.Lock()   # run_main.py 가 여러 호출을 동시에 보낼 때 비용·기록 파일을 지킨다


class BudgetExceeded(RuntimeError):
    pass


class ModelDisabled(RuntimeError):
    pass


def _price_table():
    """모델 레지스트리. 유료는 enabled=false 로 둔다(승인 뒤 바꾼다). 가격 = 100만 토큰당 USD."""
    if DEFAULT_REGISTRY.exists():
        return json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
    return {
        "qwen2.5-coder:14b": {"provider": "ollama", "enabled": True, "in": 0.0, "out": 0.0},
        "qwen2.5-coder:32b": {"provider": "ollama", "enabled": True, "in": 0.0, "out": 0.0},
        "claude-sonnet-5-5": {"provider": "anthropic", "enabled": False, "in": 2.0, "out": 10.0},
        "gpt-4o": {"provider": "openai", "enabled": False, "in": 2.5, "out": 10.0},
    }


def _hash(model, messages, temperature, seed, max_tokens):
    blob = json.dumps([model, messages, temperature, seed, max_tokens], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _post(url, body, headers, timeout=1800):
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


# ---- provider 별 전송. 키는 환경 변수에서만 읽는다. ----
def _send_ollama(model, messages, temperature, seed, max_tokens, cfg):
    url = cfg.get("url", "http://localhost:11434/v1/chat/completions")
    d = _post(url, {"model": model, "messages": messages, "temperature": temperature, "seed": seed,
                    "max_tokens": max_tokens}, {})
    u = d.get("usage") or {}
    return d["choices"][0]["message"]["content"], u.get("prompt_tokens"), u.get("completion_tokens")


def _send_openai(model, messages, temperature, seed, max_tokens, cfg):
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ModelDisabled("OPENAI_API_KEY 가 환경 변수에 없다")
    url = cfg.get("url", "https://api.openai.com/v1/chat/completions")
    d = _post(url, {"model": model, "messages": messages, "temperature": temperature, "seed": seed,
                    "max_tokens": max_tokens}, {"Authorization": f"Bearer {key}"})
    u = d.get("usage") or {}
    return d["choices"][0]["message"]["content"], u.get("prompt_tokens"), u.get("completion_tokens")


def _send_anthropic(model, messages, temperature, seed, max_tokens, cfg):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ModelDisabled("ANTHROPIC_API_KEY 가 환경 변수에 없다")
    sys_txt = "\n".join(m["content"] for m in messages if m["role"] == "system")
    conv = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] != "system"]
    url = cfg.get("url", "https://api.anthropic.com/v1/messages")
    body = {"model": model, "max_tokens": max_tokens, "temperature": temperature, "messages": conv}
    if sys_txt:
        body["system"] = sys_txt
    d = _post(url, body, {"x-api-key": key, "anthropic-version": "2023-06-01"})
    text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
    u = d.get("usage") or {}
    return text, u.get("input_tokens"), u.get("output_tokens")


SENDERS = {"ollama": _send_ollama, "openai": _send_openai, "anthropic": _send_anthropic}


class ModelClient:
    def __init__(self, run_dir, registry=None, cost_cap_usd=None):
        self.run = Path(run_dir)
        self.run.mkdir(parents=True, exist_ok=True)
        self.reg = registry or _price_table()
        self.cap = cost_cap_usd
        self.calls = self.run / "_calls.jsonl"
        self.cache = self.run / "_call_cache"
        self.cache.mkdir(exist_ok=True)
        self.costfile = self.run / "_cost.json"

    def _cost(self):
        return json.loads(self.costfile.read_text(encoding="utf-8")) if self.costfile.exists() else {"usd": 0.0, "by_model": {}}

    def total_cost(self):
        return self._cost()["usd"]

    def _add_cost(self, model, pt, ct):
        with _LOCK:
            return self._add_cost_locked(model, pt, ct)

    def _add_cost_locked(self, model, pt, ct):
        p = self.reg.get(model, {})
        usd = ((pt or 0) * p.get("in", 0.0) + (ct or 0) * p.get("out", 0.0)) / 1e6
        c = self._cost()
        c["usd"] = round(c["usd"] + usd, 6)
        m = c["by_model"].setdefault(model, {"usd": 0.0, "in": 0, "out": 0, "calls": 0})
        m["usd"] = round(m["usd"] + usd, 6); m["in"] += pt or 0; m["out"] += ct or 0; m["calls"] += 1
        self.costfile.write_text(json.dumps(c, ensure_ascii=False, indent=1), encoding="utf-8")
        return usd

    def call(self, model, messages, temperature, seed, max_tokens=8192, _transport=None, cache_salt=None):
        """cache_salt: 같은 요청을 일부러 여러 번 보낼 때(예: 예산 대조의 다시 번역) 호출 자리마다 다른 캐시 키를 쓴다.
        모델에 보내는 내용은 바뀌지 않는다. None 이면 기존 캐시 키 그대로."""
        if model not in self.reg:
            raise ModelDisabled(f"레지스트리에 없는 모델: {model}")
        cfg = self.reg[model]
        if not cfg.get("enabled", False):
            raise ModelDisabled(f"{model} 은 enabled=false 다(승인 전까지 부르지 않는다)")
        h = _hash(model, messages, temperature, seed, max_tokens)
        if cache_salt is not None:
            h = hashlib.sha256((h + "|" + str(cache_salt)).encode("utf-8")).hexdigest()
        cf = self.cache / f"{h}.json"
        if cf.exists():                                   # E3: 이미 한 호출은 다시 결제하지 않는다
            rec = json.loads(cf.read_text(encoding="utf-8"))
            return rec["text"], {**rec["meta"], "cached": True}
        # E2: 상한 확인(이번 호출 전의 누적으로 판단; 유료일 때만 의미)
        if self.cap is not None and cfg.get("in", 0.0) + cfg.get("out", 0.0) > 0 and self.total_cost() >= self.cap:
            raise BudgetExceeded(f"누적 비용 ${self.total_cost():.2f} 가 상한 ${self.cap} 에 닿았다")
        send = _transport or SENDERS[cfg["provider"]]
        t0 = time.time()
        text, pt, ct = send(model, messages, temperature, seed, max_tokens, cfg)
        usd = self._add_cost(model, pt, ct)
        meta = {"model": model, "provider": cfg["provider"], "temperature": temperature, "seed": seed,
                "max_tokens": max_tokens, "prompt_tokens": pt, "completion_tokens": ct,
                "latency_s": round(time.time() - t0, 1), "usd": round(usd, 6), "hash": h, "cached": False}
        cf.write_text(json.dumps({"text": text, "meta": meta}, ensure_ascii=False), encoding="utf-8")
        with _LOCK, self.calls.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": round(time.time()), **meta,
                                "request_hash": h, "n_messages": len(messages)}, ensure_ascii=False) + "\n")
        return text, meta
