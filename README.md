# OSS Runner API 🚀  
> **"웹에서 클릭 한 번으로 오픈소스를 실행하고, 로그까지 실시간 스트리밍!"**  
FastAPI + asyncio 기반의 경량 오픈소스 실행·모니터링 백엔드 서비스

---

## 📂 프로젝트 개요

이 서비스는 **브라우저에서 특정 오픈소스 스크립트/도구를 실행하고**,  
**그 실행 상태와 로그를 API 형태로 조회/스트리밍**할 수 있도록 설계되었습니다.

대표적인 활용 시나리오:

- Prowler, Trivy, Syft 등의 **보안/컴플라이언스 오픈소스 실행**
- 웹 UI 버튼 클릭 → 서버에서 실행 → 실시간 로그 스트리밍
- 여러 개의 실행(run) 목록 관리
- 개별 run을 중단/조회/로그 추적

---

## ✨ 핵심 기능

| Endpoint | 설명 |
|----------|------|
| `GET /health` | API 상태, 실행 통계 리턴 |
| `GET /opensource-list` | 현재 실행 가능한 오픈소스 목록 조회 |
| `POST /set/{name}` | `{name}` 오픈소스 실행 후 run_id 반환 |
| `GET /runs` | 모든 실행 목록 조회 |
| `GET /runs/{run_id}` | 단일 실행(run) 상세 정보 |
| `GET /runs/{run_id}/logs` | **Server-Sent Events(SSE)** 기반 실시간 로그 스트리밍 |
| `POST /runs/{run_id}/stop` | 실행 중인 오픈소스 중단 |

⚠️ **모든 실행 가능한 명령어는 화이트리스트 방식으로 고정**되어 있어  
임의 명령 실행 취약점에 대한 초기 보안이 보장됩니다.

---

## 🧱 파일 구조

```text
oss-runner/
├─ app/
│  ├─ main.py          # FastAPI 엔트리
│  ├─ core/            # 환경변수 로드 등 설정
│  ├─ models/          # 데이터 모델 (RunRecord 등)
│  ├─ services/        # RunnerService (실행/로그/중단)
│  ├─ utils/           # SSE 유틸
│  └─ routers/         # 각종 API 엔드포인트
├─ logs/               # 실행 로그 저장 경로 (docker volume 가능)
├─ .env.example
├─ requirements.txt
├─ Dockerfile
└─ run.sh
🐳 Docker로 실행하기
1. 소스 클론
bash
코드 복사
git clone https://github.com/<you>/oss-runner.git
cd oss-runner
2. 환경변수 설정
bash
코드 복사
cp .env.example .env
.env 파일 안의 LOG_DIR, APP_NAME 등을 원하는 값으로 수정하세요.

3. Docker 이미지 빌드
bash
코드 복사
docker build -t oss-runner:latest .
4. Docker 컨테이너 실행
bash
코드 복사
docker run --rm -it \
  -p 8000:8000 \
  -v "$(pwd)/logs:/app/logs" \
  --name oss-runner \
  oss-runner:latest
-v $(pwd)/logs:/app/logs : 컨테이너 로그를 로컬 logs/ 디렉토리로 마운트

FastAPI 문서 자동 생성: http://localhost:8000/docs

📝 API 예시
1. 실행 가능 목록 확인
bash
코드 복사
curl http://localhost:8000/opensource-list
응답 예:

json
코드 복사
{
  "items": [
    {
      "name": "hello",
      "description": "hello runnable command",
      "cmd": ["bash", "-lc", "echo 'Hello OSS Runner'; ..."]
    }
  ]
}
2. 오픈소스 실행
bash
코드 복사
curl -X POST http://localhost:8000/set/hello
json
코드 복사
{
  "run": {
    "run_id": "f6a54aa7-e8bb-4c18-b5a4-2c98773740c0",
    "name": "hello",
    ...
  }
}
3. 실시간 로그 수신 (SSE)
bash
코드 복사
curl -N http://localhost:8000/runs/<run_id>/logs
또는 프론트 JavaScript에서:

js
코드 복사
const es = new EventSource(`/runs/${runId}/logs`);
es.onmessage = (e) => console.log(e.data);
🛠️ 커스터마이징
오픈소스 목록 수정:
👉 app/services/runner.py 내부 DEFAULT_OPEN_SOURCE_CMDS 딕셔너리 수정

python
코드 복사
DEFAULT_OPEN_SOURCE_CMDS = {
    "hello": ["bash", "-lc", "echo 'Hello'"],
    "prowler-list": ["prowler", "aws", "--list-checks"]
}
보안강화 (추천):

커맨드 화이트리스트 고정

리눅스 cgroups, ulimit, timeout 사용으로 자원 제한

인증/인가 미들웨어 추가

🧪 로컬 개발 (Docker 없이)
bash
코드 복사
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
bash run.sh
🧱 기술 스택
FastAPI – 경량 API 백엔드

asyncio.subprocess – 비동기 프로세스 실행 & I/O

Server-Sent Events (SSE) – 실시간 로그 스트리밍

Docker – 배포 포터빌리티 및 실행 격리

Pydantic v2 – 데이터 검증 및 직렬화

📌 TODO / 향후 업데이트
 WebSocket 로그 브로드캐스트

 오픈소스 설정 DB화(YAML/SQLite/Redis)

 runc/cgroups 기반 CPU/메모리 제한

 API Key / JWT 인증 추가

 실행 결과물 S3 업로드

 UI 데모 제공 (React/Next.js)

