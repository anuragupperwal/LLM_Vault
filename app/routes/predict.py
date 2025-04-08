from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.auth import get_current_user
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

class PromptRequest(BaseModel):
    prompt: str

@router.post("/predict")
def predict(request: PromptRequest, user=Depends(get_current_user)):
    try:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[
                {"role": "user", "content": request.prompt}
            ]
        )
        reply = response.choices[0].message.content
        return {"response": reply}
    except Exception as e:
        return {"error": str(e)}