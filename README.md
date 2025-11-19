# DSPM Opensource Runner

이 프로젝트는 FastAPI 기반으로 Prowler · Scout Suite · Steampipe · Cloud Custodian 등 주요 오픈소스 보안 도구를 실행하고, 실행 결과/로그/산출물을 관리하는 백엔드입니다. 실행 이력(`runs/…`)은 자동으로 저장되고, SSE 기반 실시간 로그 스트리밍 및 증적 PDF 생성까지 제공합니다.

## 주요 기능

- `/oss/api/run/{tool}` : 화이트리스트된 오픈소스 도구 실행 (예: prowler, custodian, steampipe, scout)
- `/oss/api/runs/{run_id}` : 실행 상태·산출물 조회
- `/oss/api/runs/{run_id}/logs` : Server-Sent Events로 실시간 로그 스트리밍
- `/oss/api/oss/{tool}/runs/latest` : 각 도구별 최신 실행 결과/파일
- `/oss/api/evidence/pdf` : Prowler/Steampipe/Scout/Custodian 결과 기반 증적 PDF 생성
- `/health`, `/oss/api/oss-list`, `/runs` 등 다양한 모니터링/관리 API

## 로컬 실행

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # 필요 시 환경 변수 수정
bash run.sh                 # uvicorn app.main:app --host 0.0.0.0 --port 8800
```

로컬 테스트 중 최신 실행 결과가 없으면 `GET /oss/api/oss/{tool}/runs/latest`는 404를 반환합니다. 먼저 `/oss/api/run/{tool}`을 호출해 run 데이터를 생성한 뒤 조회해 주세요.

## 백그라운드 실행 (setup.sh)

로컬에서 uvicorn을 백그라운드로 돌리고 `log.txt`로만 로그를 보고 싶다면 `setup.sh`를 실행합니다.

```bash
./setup.sh
tail -f log.txt
```

PID는 `oss_runner.pid`에 기록되며, 필요 시 `kill $(cat oss_runner.pid)`으로 중지할 수 있습니다.

## Docker 사용

### 1) 직접 빌드

```bash
docker build -t sage-oss .
docker run -d --name sage-oss -p 8800:8800 sage-oss
```

- 백그라운드 실행 후 `docker logs -f sage-oss` 또는 `docker logs sage-oss > log.txt`로 로그 저장 가능
- 컨테이너에 진입하려면 `docker exec -it sage-oss /bin/bash`
- 중지/삭제: `docker stop sage-oss && docker rm sage-oss`

### 2) Docker Hub 이미지 사용

```bash
docker pull comnyang/sage-oss:latest
docker run -d --name sage-oss -p 8800:8800 comnyang/sage-oss:latest
```

- 로그 확인: `docker logs sage-oss`
- 다시 실행: `docker start sage-oss`
- 완전히 제거: `docker rm -f sage-oss`

Docker 컨테이너를 백그라운드로 띄운 뒤 터미널은 바로 반환되며, FastAPI 문서는 `http://localhost:8800/docs`에서 확인 가능합니다.

## AWS Marketplace 보안/자격 증명 대응

이 프로젝트는 AWS Marketplace 컨테이너 제품 요구 사항(보안, 고객 데이터, 자격 증명 정책 등)에 맞춰 다음을 준수합니다.

- **IAM 전용 자격 증명**: 컨테이너는 `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` 입력을 요구하지 않습니다. 실행 시 Pod Identity(EKS IRSA) 또는 ECS/Fargate Task Role에 부여된 권한으로만 AWS API를 호출합니다. 교차 계정이 필요한 경우 `iam_role_arn` 옵션으로 STS AssumeRole을 수행합니다.
- **최소 권한**: 컨테이너 실행 계정은 Dockerfile에서 생성한 `dspm` 비루트 사용자이며, 루트 권한 없이 FastAPI/CLI를 구동합니다.
- **자동화된 배포**: 이미지 안에 모든 실행 바이너리(prowler, custodian, scout, powerpipe 등)를 포함/설치하며 외부에서 추가 이미지를 가져오지 않습니다.
- **보안 비밀 미저장**: API 페이로드에는 IAM External ID 등 민감 값이 보관되지 않고, 실행 디렉터리(`runs/.../result.json`)에도 마스킹된 값만 남습니다.

AWS Marketplace/EKS에 배포할 때는 서비스 계정에 다음 권한을 부여해야 합니다.

1. Steampipe/Prowler/Scout/Custodian가 대상 계정에서 점검할 IAM 정책.
2. 교차 계정 점검 시 `sts:AssumeRole` 로 목표 `iam_role_arn`을 수임할 권한.
3. (선택) `iam_session_duration` 범위(기본 1시간)에 맞는 STS 정책.

## IAM Role 기반 실행

새로운 실행 옵션을 통해 API 호출 시 IAM Role을 지정할 수 있습니다. 모든 AWS Provider 기반 도구에서 다음 파라미터를 지원합니다.

- `iam_role_arn` : STS AssumeRole 대상 ARN. 생략 시 컨테이너에 붙은 기본 IAM 역할을 그대로 사용합니다.
- `iam_session_name` : 세션 이름 (기본 `sage-oss-xxxxx`).
- `iam_session_duration` : 세션 유지 시간(초). 900~43200 사이 숫자를 받으며 기본 3600초입니다.
- `iam_external_id` : 필요 시 서드파티 계정에서 요구하는 External ID.

예시:

```bash
curl -sS -X POST http://localhost:8800/oss/api/oss/prowler/run \
  -H 'Content-Type: application/json' \
  -d '{
        "provider": "aws",
        "region": "ap-northeast-2",
        "iam_role_arn": "arn:aws:iam::123456789012:role/SageScanner",
        "iam_session_name": "sage-marketplace",
        "iam_session_duration": 1800
      }'
```

컨테이너는 위 정보를 기반으로 STS를 호출하여 임시 자격 증명을 만든 뒤, 하위 CLI(`prowler`, `powerpipe`, `scout`, `custodian`)에 `AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN` 환경 변수를 주입합니다. 로컬 개발 목적으로만 `profile` 옵션(AWS CLI Profile)을 사용할 수 있지만, AWS Marketplace 배포 시에는 `iam_role_arn` 기반 방식만 사용해 주세요.

## 생성 산출물/로그 위치

- `runs/<YYYYMM>/<run_id>/` : 각 도구 실행 산출물(result.json, outputs 디렉터리 등)
- `log.txt` : `setup.sh` 로컬 백그라운드 실행 로그
- Docker 기반 실행 시 기본적으로 stdout에 로그가 출력되며, `docker logs`를 이용해 필요 시 파일로 리다이렉션합니다.

## 참고

- 실행 가능한 도구/옵션은 `app/services/oss_service.py`에 정의되어 있습니다.
- `app/services/evidence_report_service.py`는 Prowler/Scout/Steampipe/Custodian 결과를 분석해 PDF와 메타 정보를 생성합니다.
- run 데이터를 하나도 생성하지 않은 상태에서 “최신 결과” API를 조회하면 404가 정상 응답입니다. 반드시 한 번 이상 해당 도구를 실행해 run 디렉터리를 만들어 주세요.
