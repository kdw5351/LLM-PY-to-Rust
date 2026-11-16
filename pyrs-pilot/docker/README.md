# docker/ — 격리 실행 (제안서 5절 "빌드와 실행을 나눈다")

`config.toml` `[sandbox] mode = "docker"` 로 하네스가 이 경로를 쓴다. **2026-11-06 이 PC(Docker 29.9.2)에서 참조 해답으로 실제 검증했다**: 6개 Python + 2개 Rust(T5·T6) 참조가 docker 모드 `check_references` 에서 기능 8/8·공격 전부 방어·무효 0, 고아 컨테이너 0. 이미지 크기 `pyrs-pilot/python` 179MB, `pyrs-pilot/rust` 1.33GB.

Git Bash 에서 `docker` 를 직접 칠 때만 `MSYS_NO_PATHCONV=1` 이 필요하다(`/scratch` 가 `C:/Program Files/Git/scratch` 로 변형되는 것 방지). 하네스는 Python `subprocess` 로 리스트 인자를 넘기므로 이 문제가 없다. `docker` 가 PATH 에 없으면 `C:\Program Files\Docker\Docker\resources\bin` 를 추가한다.

## 두 단계, 세 네트워크

| 단계 | 네트워크 | 접속 가능한 곳 | 하는 일 |
| --- | --- | --- | --- |
| Python 빌드 | `pyrs-registry` (`--internal`) | PyPI 캐시 프록시 `pypi-mirror` 만 | `_venv` 생성, `pip install`, `py_compile`, `pip freeze` |
| Rust fetch | `fetch_network`(기본 `bridge`) | crates.io(인터넷) | `cargo fetch` — 의존성·`Cargo.lock` 확보. 캐시 볼륨에 쌓인다 |
| Rust build | `pyrs-registry` (`--internal`) | 없음(오프라인) | `CARGO_NET_OFFLINE=true cargo build --release --offline` |
| 실행(명령행) | `--network none` | 없음 | 기능·공격·예시 입력. `--memory --pids-limit --read-only`, 소스 `/work`(ro), `/scratch`(rw), `/tools`(ro) |
| 실행(서버 T3) | `pyrs-run` (`--internal`) | 없음(외부 차단) | 서버를 띄우고, **같은 컨테이너 안에서 `docker exec` 로 프로브**(`tools/net_probe.py`)가 `127.0.0.1:port` 에 접속 |

**crates 전체 미러(panamax)는 쓰지 않는다.** Rust 는 fetch(네트워크 허용)로 의존성을 한 번 받아 `Cargo.lock` 과 캐시 볼륨에 남기고, build 는 오프라인으로 한다. `Cargo.lock` + 캐시가 이미 있으면 fetch 가 죽어 있어도 오프라인 빌드가 된다(확인함). 날짜 고정은 fetch 시점으로 기록한다(`pip_freeze.txt`, `Cargo.lock`).

**서버 과제는 포트를 매핑하지 않는다.** `--internal` 네트워크의 컨테이너는 호스트로 포트 publish 가 **닿지 않는다**(직접 확인: internal+`-p` → 연결 안 됨, bridge+`-p` → 200). 그래서 호스트 프로브 대신 서버 컨테이너 안에서 `docker exec` 로 프로브를 돌린다. 서버가 `127.0.0.1` 에만 바인드해도(참조 T3 가 그렇다) 같은 네트워크 네임스페이스라 닿고, 외부 네트워크는 여전히 막혀 있다.

**고아 컨테이너 방지.** 모든 컨테이너에 `--name pyrs_<rand>` 과 `--init` 을 붙인다. `--rm` 은 정상 종료 때만 지우므로, 명령행 과제의 timeout·서버 과제 종료 때는 `docker rm -f <name>` 을 따로 부른다(`sandbox.docker_rm`; `Popen.terminate()` 는 docker CLI 클라이언트만 죽이고 컨테이너는 남기 때문). 검증 실행에서 고아 0 확인.

## 설치 순서

```bash
# 1) 이미지
docker build -f docker/Dockerfile.python -t pyrs-pilot/python docker
docker build -f docker/Dockerfile.rust   -t pyrs-pilot/rust   docker

# 2) 네트워크
docker network create --internal pyrs-registry
docker network create --internal pyrs-run
# fetch_network 는 기본 bridge(이미 있음). 다른 걸 쓰려면 config 의 fetch_network 에 적는다.

# 3) PyPI 캐시 프록시 (proxpi; devpi 이미지는 Docker Hub 에 없다)
docker run -d --name pypi-mirror -p 127.0.0.1:5000:5000 epicwink/proxpi
docker network connect pyrs-registry pypi-mirror      # bridge(인터넷)와 pyrs-registry 양쪽에 연결
#   proxpi 는 인덱스 경로가 /index/ 이고 포트 5000 이다. 한 번 받은 패키지는 캐시한다.
#   엄밀한 날짜 고정이 필요하면 proxpi 대신 스냅샷을 지원하는 bandersnatch 로 바꾼다.

# 4) cargo 레지스트리 캐시 볼륨
docker volume create pyrs-pilot-cargo
```

`config.toml` 기본값(이미 반영):
```toml
[sandbox]
mode = "docker"
pip_index_url = ""          # 빈 값이면 http://pypi-mirror:5000/index/
fetch_network = "bridge"
cargo_mirror_index = ""     # 쓰지 않음
```

## 검증 방법

```bash
# config.toml 의 mode 를 "docker" 로 두고:
python -m harness.check_references --langs python rust
```
전부 `ok` 가 나오면 된다. 미러·네트워크·볼륨이 위대로 준비되어 있어야 한다. 참조 해답은 사람이 쓴 코드라 `--i-know-local-is-unsafe` 가 필요 없다.

## 하네스가 만드는 명령 (요약)

Rust build(오프라인):
```
docker run --rm --init --name pyrs_XXXX --network pyrs-registry \
  -v <sol>:/work -v pyrs-pilot-cargo:/usr/local/cargo/registry \
  -e CARGO_NET_OFFLINE=true --memory 2g --pids-limit 256 \
  pyrs-pilot/rust sh -c "cd /work && cargo build --release --offline"
```
실행(명령행):
```
docker run --rm --init --name pyrs_XXXX --network none --memory 512m --memory-swap 512m \
  --pids-limit 256 --read-only -v <sol>:/work:ro -v <scratch>:/scratch -v <tools>:/tools:ro \
  -e CANARY_DIR=/scratch/canary -w /scratch \
  pyrs-pilot/rust /work/target/release/app inspect /scratch/fixtures/<file>
```
실행(서버) + 프로브:
```
docker run --rm --init --name pyrs_SRV --network pyrs-run ... pyrs-pilot/python python /work/main.py serve --port P ...
docker exec pyrs_SRV python3 /tools/net_probe.py /scratch/_probe_in.json
docker rm -f pyrs_SRV
```

## 확인된 격리 성질 (2026-11-06)

- 빌드 이미지 2개, 네트워크 `pyrs-registry`·`pyrs-run`(internal), 볼륨 `pyrs-pilot-cargo` 생성됨.
- 실행 컨테이너: internal 외부 차단 ✓, `--network none` ✓, `--read-only` 루트 쓰기 거부 ✓, `/scratch` 쓰기 ✓, `canary` 실행 시 `/scratch/canary/hit` 생성 ✓, 512m 에서 900MB 할당 → OOM Killed ✓.
- Rust: `Cargo.lock` + 캐시 볼륨이 있으면 미러가 죽어 있어도 오프라인 빌드 ✓(T6 serde-pickle).
- 참조 해답 6 Python + 2 Rust 가 docker 모드 `check_references` 전부 `ok` ✓, 고아 컨테이너 0 ✓.

## 남은 확인 사항

- `mem_limit` 과제별 값은 `python -m harness.measure_memory`(psutil 필요) 로 참조 구현 피크의 2배를 재서 `[tasks_cfg.<id>]` 에 적는다. 지금 T6 은 임시 512m.
- proxpi 는 "처음 받은 시점" 캐시라 엄밀한 날짜 고정은 아니다. 사전 등록용으로는 bandersnatch 스냅샷을 권한다.
- `fetch_network` 를 bridge(인터넷)로 두므로 fetch 단계는 외부에 나간다. 완전 오프라인 재현은 캐시 볼륨을 먼저 채운 뒤 fetch 를 건너뛰는 방식으로 한다(build 는 이미 오프라인).
