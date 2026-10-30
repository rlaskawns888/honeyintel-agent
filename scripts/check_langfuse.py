from dotenv import load_dotenv
load_dotenv()

from langfuse import get_client, observe

langfuse = get_client()

@observe(name="check-langfuse")
def ping(msg: str) -> str:
    return f"pong: {msg}"

if __name__ == "__main__":
    print("auth:", langfuse.auth_check())
    print(ping("hello"))
    langfuse.flush()  # 스크립트 종료 전 전송 보장