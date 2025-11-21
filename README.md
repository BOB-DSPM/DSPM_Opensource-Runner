# DSPM Opensource-Runner

## 프로젝트 개요

이 프로젝트는 **보안 스캐닝 오픈소스 도구들을 웹 인터페이스로 실행하고 모니터링할 수 있는 백엔드 서비스**입니다.

### 주요 목적
- Prowler, Trivy, Syft 등의 보안 검사 도구를 웹에서 실행
- 실행 중인 프로세스의 로그를 실시간으로 스트리밍
- 여러 실행 작업을 동시에 관리

### 지원하는 보안 오픈소스 도구

#### 1. Prowler
- **목적**: AWS 계정 및 서비스 보안 점검
- **출력**: JSON, CSV, HTML 형식의 컴플라이언스 리포트
- **특징**: CIS, PCI-DSS, ISO 27001 등 다양한 보안 프레임워크 지원
- **주요 검사 항목**: IAM 권한, CloudTrail 로깅, 암호화 설정, 네트워크 보안 등

#### 2. Cloud Custodian
- **목적**: 클라우드 자원의 정책 기반 관리 및 자동화
- **출력**: JSON 리포트, 실행 로그
- **특징**: 정책-as-코드 방식으로 클라우드 자원 탐지 및 시정
- **주요 검사 항목**: IAM 역할, ELB 설정, 액세스 키 관리 등

#### 3. Steampipe (Powerpipe mods)
- **목적**: 클라우드 인프라 컴플라이언스 점검
- **출력**: JSON, CSV, HTML 형식의 벤치마크 리포트
- **특징**: SQL 기반 클라우드 인프라 쿼리 및 컴플라이언스 평가
- **주요 검사 항목**: CIS Benchmark, AWS Well-Architected Framework

#### 4. Scout Suite
- **목적**: 멀티 클라우드 보안 감사
- **출력**: 인터랙티브 HTML 리포트, JSON 데이터
- **특징**: AWS, Azure, GCP 등 다양한 클라우드 환경 지원
- **주요 검사 항목**: 네트워크 보안, IAM 설정, 스토리지 접근 제어 등

---

## 동작 원리

### 1. 오픈소스 실행 과정

```
사용자 요청 → FastAPI 서버 → asyncio subprocess 실행 → 오픈소스 도구 실행
```

#### 단계별 설명

1. **오픈소스 등록** (`app/services/runner.py`)
   - 실행 가능한 오픈소스 명령어가 `DEFAULT_OPEN_SOURCE_CMDS` 딕셔너리에 사전 정의됨
   - 각 오픈소스는 이름과 실행 명령어로 구성
   - 예시: `"prowler": ["prowler", "aws", "--list-checks"]`

2. **실행 요청** (POST `/set/{name}`)
   - 사용자가 특정 오픈소스 이름으로 실행 요청
   - 서버는 고유한 `run_id` (UUID)를 생성
   - asyncio.subprocess를 통해 비동기로 프로세스 실행

3. **로그 수집**
   - 실행 중인 프로세스의 stdout/stderr를 실시간으로 캡처
   - `logs/{run_id}.log` 파일에 로그 저장
   - 프로세스 상태(실행 중/완료/실패)를 메모리에 저장

4. **실시간 모니터링** (GET `/runs/{run_id}/logs`)
   - Server-Sent Events (SSE) 기술로 로그 스트리밍
   - 프론트엔드에서 EventSource API로 연결하여 실시간 로그 수신
   - 프로세스 종료 시까지 계속 로그 전송

### 2. 생성되는 파일 및 데이터

#### 생성되는 파일
- **로그 파일**: `logs/{run_id}.log`
  - 각 실행마다 고유한 로그 파일 생성
  - 오픈소스 도구의 표준 출력 및 에러 출력이 저장됨
  - Docker 볼륨으로 마운트하여 영속성 보장

#### 메모리 데이터 구조 (RunRecord)
```python
{
    "run_id": "f6a54aa7-e8bb-4c18-b5a4-2c98773740c0",  # 고유 실행 ID
    "name": "prowler",                                  # 오픈소스 이름
    "status": "running" | "completed" | "failed",       # 실행 상태
    "started_at": "2024-11-21T10:30:00",               # 시작 시간
    "finished_at": "2024-11-21T10:35:00" | null,       # 종료 시간
    "exit_code": 0 | 1 | null,                         # 종료 코드
    "log_path": "/app/logs/{run_id}.log"               # 로그 파일 경로
}
```

### 3. 최종 결과물

#### API를 통해 얻을 수 있는 정보

1. **실행 통계** (GET `/health`)
   ```json
   {
     "status": "ok",
     "total_runs": 15,
     "running": 2,
     "completed": 10,
     "failed": 3
   }
   ```

2. **실행 목록** (GET `/runs`)
   - 모든 실행 작업의 목록과 상태 조회
   - 각 작업의 시작/종료 시간, 상태 확인

3. **개별 실행 정보** (GET `/runs/{run_id}`)
   - 특정 실행 작업의 상세 정보
   - 로그 파일 경로, 실행 시간, 종료 코드 등

4. **실시간 로그** (SSE)
   - 실행 중인 오픈소스의 출력을 실시간으로 수신
   - 프론트엔드에서 터미널처럼 표시 가능

#### 오픈소스 도구의 실행 결과
- **Prowler**: AWS 보안 검사 결과 (JSON, CSV 등)
- **Trivy**: 컨테이너 이미지 취약점 스캔 결과
- **Syft**: SBOM (Software Bill of Materials) 생성
- 각 도구가 생성하는 결과 파일은 도구의 설정에 따라 다름

#### 통합 증적 보고서 (선택 사항)
본 시스템을 활용하면 **종합 보안 평가 리포트 PDF**를 자동 생성할 수 있습니다.

**리포트 구성 예시**:
- **종합 요약**: 전체 점검 개요 및 취약점 통계
- **세부 취약점**: Severity별(CRITICAL/HIGH/MEDIUM/LOW) 상세 분석
- **주요 진단 결과**: 각 도구별 상위 10건 취약점
- **도구별 실행 상세**: Prowler, Scout Suite, Steampipe, Cloud Custodian 결과
- **산출물 목록**: 생성된 모든 리포트 파일 및 로그

이러한 PDF 리포트는 다음을 포함합니다:
```
총 294건의 취약점 식별
├─ CRITICAL: 3건 (루트 계정 액세스 키, MFA 미설정 등)
├─ HIGH: 29건 (CloudTrail 미설정, IAM 정책 취약점 등)
├─ MEDIUM: 221건
└─ LOW: 41건

생성된 증적 파일: 125개 이상 (JSON, CSV, HTML 등)
```

---

## 아키텍처 구조

```
┌─────────────────┐
│  Web Frontend   │  (React, Vue 등)
└────────┬────────┘
         │ HTTP/SSE
         ↓
┌─────────────────────────────────┐
│      FastAPI Server             │
│  ┌──────────────────────────┐   │
│  │  Routers (API Endpoints) │   │
│  └───────────┬──────────────┘   │
│              ↓                  │
│  ┌──────────────────────────┐   │
│  │   RunnerService          │   │
│  │  - 프로세스 관리          │   │
│  │  - 로그 수집              │   │
│  │  - 상태 추적              │   │
│  └───────────┬──────────────┘   │
│              ↓                  │
│  ┌──────────────────────────┐   │
│  │  asyncio.subprocess      │   │
│  └───────────┬──────────────┘   │
└──────────────┼──────────────────┘
               ↓
    ┌──────────────────┐
    │  오픈소스 도구    │
    │  - Prowler       │
    │  - Trivy         │
    │  - Syft          │
    └──────┬───────────┘
           ↓
    ┌──────────────┐
    │  로그 파일    │
    │  logs/*.log  │
    └──────────────┘
```

---

## 데이터 흐름

### 실행 시작
```
1. POST /set/prowler
   ↓
2. RunnerService.start_run("prowler")
   ↓
3. UUID 생성 (run_id)
   ↓
4. asyncio.create_subprocess_exec([prowler 명령어])
   ↓
5. RunRecord 생성 및 저장 (메모리)
   ↓
6. 로그 파일 생성 (logs/{run_id}.log)
   ↓
7. run_id 반환
```

### 로그 스트리밍
```
1. GET /runs/{run_id}/logs (EventSource 연결)
   ↓
2. 로그 파일 열기 (tail -f 방식)
   ↓
3. 새로운 로그 라인 감지
   ↓
4. SSE 이벤트로 전송 (data: {로그 내용})
   ↓
5. 프로세스 종료 시 연결 종료
```

---

## 보안 특징

### 명령어 실행 보안
- **화이트리스트 기반**: `DEFAULT_OPEN_SOURCE_CMDS`에 등록된 명령어만 실행 가능
- **사용자 입력 차단**: 사용자가 임의의 명령어를 실행할 수 없음
- **프리셋 명령어만 허용**: 사전 정의된 안전한 명령어만 실행

### 향후 보안 강화 계획
- cgroups를 통한 CPU/메모리 제한
- ulimit으로 리소스 제한
- timeout으로 실행 시간 제한
- API 인증/인가 추가 (JWT, API Key)

---

## 활용 시나리오

### 1. 보안 대시보드 구축
```
웹 UI → 버튼 클릭 ("AWS 보안 검사 실행")
      ↓
      FastAPI → Prowler 실행
      ↓
      실시간 로그 → 대시보드에 표시
      ↓
      결과 저장 → S3 또는 DB에 저장
```

### 2. CI/CD 파이프라인 통합
```
GitHub Actions
      ↓
      POST /set/trivy (컨테이너 이미지 스캔)
      ↓
      로그 수집 → 빌드 로그에 통합
      ↓
      취약점 발견 시 빌드 실패
```

### 3. 스케줄링 작업
```
크론잡 또는 스케줄러
      ↓
      주기적으로 POST /set/prowler
      ↓
      자동 보안 검사 실행
      ↓
      결과를 Slack/이메일로 전송
```

---

## 확장 가능성

### 오픈소스 추가 방법
`app/services/runner.py` 파일의 `DEFAULT_OPEN_SOURCE_CMDS`에 새로운 명령어 추가:

```python
DEFAULT_OPEN_SOURCE_CMDS = {
    "prowler": ["prowler", "aws", "--list-checks"],
    "trivy": ["trivy", "image", "nginx:latest"],
    "syft": ["syft", "packages", "alpine:latest"],
    # 새로운 도구 추가
    "my-tool": ["my-tool", "--scan", "--output", "json"]
}
```

### 설정 외부화
현재는 코드에 하드코딩되어 있지만, 향후 다음과 같이 확장 가능:
- YAML 파일로 오픈소스 목록 관리
- 데이터베이스(SQLite, PostgreSQL)에서 설정 로드
- Redis를 통한 동적 설정 업데이트

---

## 기술 스택 요약

| 구성 요소 | 기술 | 역할 |
|-----------|------|------|
| 웹 프레임워크 | FastAPI | RESTful API 제공 |
| 비동기 처리 | asyncio | 비동기 프로세스 실행 |
| 실시간 통신 | Server-Sent Events | 로그 스트리밍 |
| 프로세스 관리 | asyncio.subprocess | 오픈소스 도구 실행 |
| 데이터 검증 | Pydantic v2 | 요청/응답 검증 |
| 컨테이너화 | Docker | 격리된 실행 환경 |
| 로그 저장 | 파일 시스템 | 텍스트 로그 파일 |

---

## 실행 예시

### 1. Prowler AWS 보안 검사 실행
```bash
# 실행
curl -X POST http://localhost:8000/set/prowler

# 응답
{
  "run": {
    "run_id": "abc-123-def-456",
    "name": "prowler",
    "status": "running",
    "started_at": "2024-11-21T10:00:00"
  }
}

# 실시간 로그 확인
curl -N http://localhost:8000/runs/abc-123-def-456/logs
```

### 2. 웹 브라우저에서 실시간 로그
```javascript
const eventSource = new EventSource('/runs/abc-123-def-456/logs');

eventSource.onmessage = (event) => {
  console.log('로그:', event.data);
  // 화면에 로그 출력
  document.getElementById('logs').innerHTML += event.data + '\n';
};

eventSource.onerror = () => {
  console.log('로그 스트리밍 종료');
  eventSource.close();
};
```

---

## 제한사항 및 주의사항

### 현재 제한사항
1. **메모리 기반 저장소**: 서버 재시작 시 실행 기록 소실
2. **단일 서버**: 수평 확장 불가 (로드밸런싱 미지원)
3. **리소스 제한 없음**: 프로세스가 무제한 리소스 사용 가능
4. **인증 없음**: 누구나 API 호출 가능

### 프로덕션 사용 시 고려사항
- 데이터베이스 도입 (PostgreSQL, MongoDB)
- 인증/인가 시스템 추가
- 리소스 제한 (cgroups, ulimit)
- 모니터링 및 알림 (Prometheus, Grafana)
- 로그 관리 시스템 (ELK Stack, Loki)

---

## AWS Marketplace 보안/자격 증명 대응

이 시스템에서 실행하는 오픈소스 도구들은 AWS의 보안 및 컴플라이언스 요구사항을 충족하는 데 활용될 수 있습니다.

### 지원하는 보안 프레임워크
- **CIS AWS Foundations Benchmark** (v2.0, v3.0, v4.0)
- **PCI-DSS** (Payment Card Industry Data Security Standard)
- **ISO 27001** (국제 정보보안 관리체계 표준)
- **CISA** (Cybersecurity and Infrastructure Security Agency)
- **RBI Cyber Security Framework** (Reserve Bank of India)
- **AWS Well-Architected Framework**

### 컴플라이언스 자동화
본 시스템을 활용하여 다음과 같은 컴플라이언스 작업을 자동화할 수 있습니다:
- 주기적인 보안 점검 실행 (일/주/월 단위)
- 취약점 발견 시 자동 알림
- 감사를 위한 증적 자료 자동 생성
- 컴플라이언스 대시보드 구축

### AWS Marketplace 통합 시나리오
```
AWS 환경
    ↓
본 시스템 (오픈소스 러너)
    ↓
자동 보안 점검 실행
    ↓
결과 저장 (S3/RDS)
    ↓
컴플라이언스 리포트 생성
```

---

## 참고

- FastAPI 공식 문서: https://fastapi.tiangolo.com/
- Server-Sent Events: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events
- asyncio subprocess: https://docs.python.org/3/library/asyncio-subprocess.html
- Prowler: https://github.com/prowler-cloud/prowler
- Cloud Custodian: https://github.com/cloud-custodian/cloud-custodian
- Steampipe: https://steampipe.io
- Scout Suite: https://github.com/nccgroup/ScoutSuite