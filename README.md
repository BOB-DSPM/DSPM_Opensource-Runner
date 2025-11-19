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

## 생성 산출물/로그 위치

- `runs/<YYYYMM>/<run_id>/` : 각 도구 실행 산출물(result.json, outputs 디렉터리 등)
- `log.txt` : `setup.sh` 로컬 백그라운드 실행 로그
- Docker 기반 실행 시 기본적으로 stdout에 로그가 출력되며, `docker logs`를 이용해 필요 시 파일로 리다이렉션합니다.

## 참고

- 실행 가능한 도구/옵션은 `app/services/oss_service.py`에 정의되어 있습니다.
- `app/services/evidence_report_service.py`는 Prowler/Scout/Steampipe/Custodian 결과를 분석해 PDF와 메타 정보를 생성합니다.
- run 데이터를 하나도 생성하지 않은 상태에서 “최신 결과” API를 조회하면 404가 정상 응답입니다. 반드시 한 번 이상 해당 도구를 실행해 run 디렉터리를 만들어 주세요.
