# 간단 소개
`rhel9_u01_u70_fullcheck.sh`는 KISA 가이드의 **Unix 서버 취약점 분석·평가 항목(U-01 ~ U-70)** 을 RHEL 9.6 환경에서 자동 점검하도록 만든 **읽기 전용 Bash 스크립트**입니다.
목표는 운영자가 수동으로 확인해야 할 항목을 자동으로 수집해 사람이 읽기 쉬운 텍스트 리포트와 요약 로그로 제공하는 것입니다. (`python3` 의존성 제거, 순수 Bash 구현)

---

# 주요 기능 요약

* 점검 범위: **U-01 ~ U-70** (계정·파일권한·서비스·패치·로그 등)
* 출력: 사람용 상세 리포트(`.txt`) + 짧은 요약 로그(`.log`)
* 실행 권한: `sudo` 또는 root 권한 필요(시스템 설정/서비스/파일 상태 조회용)
* 안전성: **읽기 전용** (파일/설정 변경, 패치 적용 등 비파괴)

---

# 요구사항(사전 준비)

* RHEL 9.6 또는 이와 호환되는 배포판
* 기본 유틸리티: `bash`, `awk`, `grep`, `sed`, `find`, `stat`, `systemctl`, `rpm`, `dnf` 등 (표준 RHEL 환경에 기본 포함)
* 파일 복사 및 실행 권한:

  ```bash
  chmod +x rhel9_u01_u70_fullcheck.sh
  sudo ./rhel9_u01_u70_fullcheck.sh
  ```

---

# 사용법 (예시)

1. 스크립트를 서버에 업로드 (예: `/usr/local/bin/`)
2. 실행권한 부여:

   ```bash
   chmod +x /usr/local/bin/rhel9_u01_u70_fullcheck.sh
   ```
3. 루트 권한으로 실행:

   ```bash
   sudo /usr/local/bin/rhel9_u01_u70_fullcheck.sh
   ```
4. 결과 확인: 실행 후 현재 디렉터리(혹은 스크립트 내부 `OUT_DIR` 설정 위치)에 다음과 같은 폴더가 생성됩니다.

   ```
   ./rhel9_unix_check_<YYYYMMDD_HHMMSS>/
     ├─ rhel9_unix_check_<TS>.txt     ← 상세 텍스트 리포트
     └─ rhel9_unix_check_<TS>.log     ← 짧은 요약 로그
   ```

---

# 출력 형식(간단)

* **TXT(사람용)**: 각 항목별 `TIME / CODE / TITLE / STATUS / DETAIL` 블록으로 구분되어 읽기 쉬움.
* **LOG(요약)**: `CODE | TITLE | STATUS` 한 줄 요약 + 상세 메시지.

---

# 점검 항목(하이라이트)

* 계정관리: root 원격접속(U-01), 패스워드 정책(U-02~U-04, U-46~U-48), UID/GID 규칙(U-44~U-53)
* 파일/디렉터리: /etc/* 권한, SUID/SGID, world-writable, 홈디렉터리(U-05~U-17, U-55~U-59)
* 서비스: FTP/Apache/DNS/NFS/SNMP/sendmail 등(U-19~U-43)
* 패치관리: dnf 보안 업데이트 확인, 자동 업데이트 설정(U-62~U-64)
* 로그/감사: rsyslog, logrotate, faillog/lastb, sudo 로그, auditd(U-65~U-70)

> 자세한 판단 기준(권장 값: minlen ≥ 8, PASS_MAX_DAYS ≤ 90 등)은 스크립트 내 주석 참조. 일부 항목은 운영정책(조직별) 요소로 `INFO`/`WARN`으로 처리됩니다.

---

# 자주 발생한 오류 및 해결 방법 (Troubleshooting)

1. **CRLF / shebang 관련**

   ```
   /usr/bin/env: `bash\r': 그런 파일이나 디렉터리가 없습니다
   ```

   → Windows에서 편집되어 CRLF가 남아 있는 경우 발생.
   해결:

   ```bash
   sed -i 's/\r$//' rhel9_u01_u70_fullcheck.sh
   # 또는
   dos2unix rhel9_u01_u70_fullcheck.sh
   ```
   
2. **`faillog: 명령어를 찾을 수 없음`**

   * 일부 환경에 `faillog`가 없을 수 있음. 스크립트는 `command -v faillog`로 존재 여부 확인 후 호출함. (문제가 날 경우 `authconfig`/`shadow-utils` 패키지 확인)

3. **`sudo` 암호 실패**

   * 프롬프트에서 암호를 잘못 입력하면 `죄송합니다만, 다시 시도하십시오.` 발생. sudo 권한과 비밀번호 확인.

---

# 커스터마이징 (간단)

* 스크립트 상단의 `TS`/`OUT_DIR` 변수 변경으로 결과 저장 위치 바꿀 수 있음.
* 정책값(예: `minlen`, `PASS_MAX_DAYS`)을 조직 기준으로 변경하려면 각 체크 블록의 비교값을 편집하면 됩니다.
* CSV 형태가 필요하면 `emit()`을 CSV 출력 버전으로 교체 가능(간단 제공 가능).

---

# 제한 사항 및 주의점

* 일부 항목은 **운영 절차·정책(예: 패치 절차, 불필요 계정 여부)**을 평가해야 하므로 스크립트는 `INFO`/`WARN`으로 해당 자료를 수집하며 최종 판단은 사람이 수행해야 합니다.
* 스크립트는 RHEL 9.x 환경을 기준으로 작성되었습니다. 다른 배포판(우분투, CentOS7 등)은 파일 경로·명령어 차이로 일부 검사가 오작동할 수 있음.
* 스크립트는 **수정(자동 복구/패치 적용) 기능을 포함하지 않습니다.** (안전상 비파괴 원칙)

---

# 배치(크론) 등록 예시

주 1회 (월요일 03:00)에 자동으로 점검하려면:

```bash
sudo crontab -e
# 추가
0 3 * * 1 /usr/local/bin/rhel9_u01_u70_fullcheck.sh >> /var/log/rhel9_u01_u70_cron.log 2>&1
```

---

# 변경이력 (Changelog)

* v0.1 — 초기 작성 (U-01~U-70 자동점검 구조)
* v0.2 — `python3` 의존성 제거, TXT 출력으로 변경, CRLF 및 `local`/`set -u` 에러 수정, 디렉터리/파일 초기화 순서 보강
* v0.21 — 부적합(fail)인 경우 권장 조치 안내 내용 추가

---

# 라이선스 & 책임

* 이 스크립트는 **참고용/도움용**으로 제공됩니다. 운영 환경에서 실행하기 전 테스트 환경에서 충분히 검증하세요.
* 사용 중 발생한 문제에 대해 제공자가 직접적인 책임을 지지 않습니다. 필요 시 스크립트를 기반으로 조직의 보안정책에 맞게 커스터마이징 하시기 바랍니다.

---
