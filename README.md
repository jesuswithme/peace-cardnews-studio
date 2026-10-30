# 평화로운마음 카드뉴스 스튜디오

**바로 써보기 (무료 모드):** https://jesuswithme.github.io/peace-cardnews-studio/
> 웹 버전은 무료 AI·프롬프트 복사·오프라인 모드만 됩니다. **내 ChatGPT 구독 연결**은 저장소를 내려받아 `시작하기.bat`으로 실행하세요.

## 내려받기
```bash
git clone https://github.com/jesuswithme/peace-cardnews-studio.git
```
또는 [ZIP 다운로드](https://github.com/jesuswithme/peace-cardnews-studio/archive/refs/heads/main.zip)

주제 하나로 인스타 카드뉴스(표지·본문·CTA)를 만들고, 4개국어 번역·템플릿 16종·30일 시리즈 ZIP까지 뽑는 웹앱입니다.

## 실행
- **Windows**: `시작하기.bat` 더블클릭 → 브라우저가 `http://127.0.0.1:1477` 로 열립니다.
- **Mac**: `start.command` 실행 (최초 1회 `chmod +x start.command`)
- Node.js 18 이상 필요 (외부 패키지 설치 없음)
- `index.html` 을 파일로 바로 열어도 무료 AI/오프라인 모드는 동작합니다. ChatGPT 구독 연결만 서버 실행이 필요합니다.

## 생성 엔진
| 엔진 | 비용 | 비고 |
|---|---|---|
| 내 ChatGPT 구독 (문구·기획·번역) | 요금제 사용량 차감 (Plus·Pro·Go) | OpenAI 공식 *Sign in with ChatGPT* (ChatGPT plan usage). API 키 불필요 |
| 무료 AI | 무료 | Pollinations 익명 모델 (품질 보통) |
| 프롬프트 복사 | 무료 | ChatGPT/Gemini 웹에 붙여넣고 JSON 결과 붙여넣기 |
| 오프라인 | 무료 | AI 없이 기본 문구 |

## 실사 이미지 엔진
| 엔진 | 비용 | 비고 |
|---|---|---|
| ChatGPT 이미지 (기본) | 내 구독의 Codex 사용량 | Codex CLI 내장 이미지 생성(gpt-image). 1장 약 1분, 워터마크 없음. 일반 문구보다 사용량을 3~5배 빨리 씀 |
| 무료 이미지 | 무료 | Pollinations, 45초당 1장, 작은 워터마크 |

ChatGPT 이미지 준비 (최초 1회):
```bash
npm i -g @openai/codex
codex login   # "Sign in with ChatGPT" 선택
```

## ChatGPT 연결 보안
- 토큰은 브라우저 저장소가 아닌 `~/.config/peace-cardnews/credentials.json` 에만 저장됩니다. 절대 공유·커밋하지 마세요.
- 서버는 `127.0.0.1` 에만 열리며 외부에서 접속할 수 없습니다.
- 사용량·앱별 한도 관리, 연결 해제: https://chatgpt.com/settings/usage

