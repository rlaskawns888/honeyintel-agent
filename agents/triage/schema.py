from enum import Enum
from pydantic import BaseModel, Field

class TriageCategory(str, Enum):
    SCAN = "scan" #cowrie.session.connect(로그인 시도X, 1~2시도), cowrie.client.version
    BRUTEFORCE = "bruteforce" #비밀번호 대입, cowrie.login.failed
    POST_EXPLOIT = "post_exploit" #로그인 후 실제 뭔가함 (cowrie.login.success -> cowrie.command.input)
    UNKNOWN = "unknown" #판단 불가

class Indicators(BaseModel):
    urls: list[str] = Field(default_factory=list, description="세션에서 다운로드 시도한 URL")
    hashes: list[str] = Field(default_factory=list, description="수집 파일 sha256")
    commands: list[str] = Field(default_factory=list, description="핵심 명령 최대 10개")

class TriageResult(BaseModel):
    category: TriageCategory
    confidence: float = Field(ge=0.0, le=1.0) #LLM 자기 분류를 얼마나 확신 여부(0.0 이상 1.0이하) -> 범위 벗어날 경우 에러 발생
    summary: str = Field(max_length=300, description="요약")
    evidence: list[str] = Field(max_length=5, description="분류 근거")
    indicators: Indicators
    needs_investigation: bool = Field(description="IP/해시 조사 필요 여부")