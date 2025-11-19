# DSPM Opensource Runner

웹에서 클릭 한 번으로 오픈소스 보안 도구를 실행하고 로그를 실시간 스트리밍하는 FastAPI 기반 서비스입니다.

## 개요

브라우저에서 Prowler, Trivy, Syft 등의 보안 및 컴플라이언스 오픈소스 도구를 실행하고, 실행 상태와 로그를 API로 조회 및 스트리밍할 수 있습니다.

**주요 활용 시나리오:**
- 웹 UI 버튼 클릭 → 서버에서 보안 스캔 실행 → 실시간 로그 확인
- 여러 스캔 작업 동시 관리 및 모니터링
- 개별 스캔 중단 및 결과 조회

## 핵심 기능

| 엔드포인트 | 설명 |
|-----------|------|
| `GET /health` | API 상태 및 실행 통계 |
| `GET /opensource-list` | 실행 가능한 도구 목록 |
| `POST /set/{name}` | 도구 실행 후 run_id 반환 |
| `GET /runs` | 모든 실행 목록 조회 |
| `GET /runs/{run_id}` | 실행 상세 정보 |
| `GET /runs/{run_id}/logs` | 실시간 로그 스트리밍 (SSE) |
| `POST /runs/{run_id}/stop` | 실행 중단 |

**보안**: 모든 실행 가능한 명령어는 화이트리스트 방식으로 고정되어 임의 명령 실행을 방지합니다.

## 프로젝트 구조

```
oss-runner/
├── app/
│   ├── main.py              # FastAPI 진입점
│   ├── core/                # 환경 설정
│   ├── models/              # 데이터 모델 (RunRecord)
│   ├── services/            # RunnerService (실행/로그/중단)
│   ├── utils/               # SSE 유틸리티
│   └── routers/             # API 엔드포인트
├── logs/                    # 실행 로그 저장 (volume 마운트 가능)
├── .env.example             # 환경 변수 템플릿
├── requirements.txt
├── Dockerfile
└── run.sh
```

## 빠른 시작

### Docker로 실행

```bash
# 저장소 클론
git clone https://github.com/BOB-DSPM/DSPM_Opensource-Runner.git
cd DSPM_Opensource-Runner

# 환경 변수 설정
cp .env.example .env
# .env 파일에서 LOG_DIR, APP_NAME 등 수정

# Docker 이미지 빌드
docker build -t oss-runner:latest .

# 컨테이너 실행
docker run --rm -it \
  -p 8800:8000 \
  -v "$(pwd)/logs:/app/logs" \
  --name oss-runner \
  oss-runner:latest
```

API 문서: http://localhost:8800/docs

### 로컬 개발 (Docker 없이)

```bash
# 가상환경 설정
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt

# 환경 변수 설정
cp .env.example .env

# 서버 실행
bash run.sh
```

## API 사용 예시

### 1. 실행 가능한 도구 목록 조회

```bash
curl http://localhost:8800/opensource-list
```

**응답:**
```json
{
  "items": [
    {
      "name": "hello",
      "description": "hello runnable command",
      "cmd": ["bash", "-lc", "echo 'Hello OSS Runner'"]
    },
    {
      "name": "prowler-list",
      "description": "List Prowler AWS checks",
      "cmd": ["prowler", "aws", "--list-checks"]
    }
  ]
}
```

### 2. 도구 실행

```bash
curl -X POST http://localhost:8800/set/hello
```

**응답:**
```json
{
  "run": {
    "run_id": "f6a54aa7-e8bb-4c18-b5a4-2c98773740c0",
    "name": "hello",
    "status": "running",
    "started_at": "2025-01-15T10:30:00Z"
  }
}
```

### 3. 실행 목록 조회

```bash
curl http://localhost:8800/runs
```

### 4. 실행 상세 조회

```bash
curl http://localhost:8800/runs/f6a54aa7-e8bb-4c18-b5a4-2c98773740c0
```

### 5. 실시간 로그 스트리밍 (SSE)

**터미널:**
```bash
curl -N http://localhost:8800/runs/f6a54aa7-e8bb-4c18-b5a4-2c98773740c0/logs
```

**JavaScript (프론트엔드):**
```javascript
const runId = 'f6a54aa7-e8bb-4c18-b5a4-2c98773740c0';
const eventSource = new EventSource(`/runs/${runId}/logs`);

eventSource.onmessage = (event) => {
  console.log('로그:', event.data);
  // 로그를 화면에 표시
};

eventSource.onerror = (error) => {
  console.error('연결 오류:', error);
  eventSource.close();
};
```

### 6. 실행 중단

```bash
curl -X POST http://localhost:8800/runs/f6a54aa7-e8bb-4c18-b5a4-2c98773740c0/stop
```

## 커스터마이징

### 오픈소스 도구 추가

`app/services/runner.py`의 `DEFAULT_OPEN_SOURCE_CMDS` 딕셔너리를 수정하여 새로운 도구를 추가할 수 있습니다.

```python
DEFAULT_OPEN_SOURCE_CMDS = {
    "hello": ["bash", "-lc", "echo 'Hello OSS Runner'"],
    "prowler-list": ["prowler", "aws", "--list-checks"]
}
```

### 보안 강화 (권장)

1. **명령어 화이트리스트**: 실행 가능한 명령만 사전 정의
2. **리소스 제한**: cgroups, ulimit, timeout 설정
3. **인증/인가**: API Key 또는 JWT 추가
4. **로그 접근 제어**: 사용자별 로그 격리

## 환경 변수

`.env` 파일에서 설정 가능 (`.env.example` 참고)

## 기술 스택

- **FastAPI** - 고성능 비동기 웹 프레임워크
- **asyncio.subprocess** - 비동기 프로세스 실행 및 I/O
- **Server-Sent Events (SSE)** - 실시간 로그 스트리밍
- **Docker** - 컨테이너 기반 배포
- **Pydantic v2** - 데이터 검증 및 직렬화

## 프론트엔드 연동

### JavaScript (EventSource)

```javascript
const runId = 'f6a54aa7-e8bb-4c18-b5a4-2c98773740c0';
const eventSource = new EventSource(`/runs/${runId}/logs`);

eventSource.onmessage = (event) => {
  console.log('로그:', event.data);
};

eventSource.onerror = (error) => {
  console.error('연결 오류:', error);
  eventSource.close();
};
```

## 트러블슈팅

### 포트 충돌

```bash
# 다른 포트로 실행
docker run -p 8801:8000 oss-runner:latest

# 또는 .env 수정
PORT=8801
```

### 로그 파일 권한 오류

```bash
# 로그 디렉토리 권한 설정
mkdir -p logs
chmod 755 logs
```

### Docker 볼륨 마운트 오류

```bash
# 절대 경로 사용
docker run -v /absolute/path/to/logs:/app/logs oss-runner:latest
```

### SSE 연결 끊김

```bash
# 타임아웃 설정 확인
# nginx 사용 시
proxy_read_timeout 300s;
proxy_send_timeout 300s;
```