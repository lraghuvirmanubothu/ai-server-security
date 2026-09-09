from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from ai_defense import defense_engine

app = FastAPI(title="Secure AI API Gateway")

class PromptPayload(BaseModel):
    prompt: str

@app.post("/v1/chat")
async def handle_chat(payload: PromptPayload, request: Request):
    client_ip = request.client.host or "127.0.0.1"
    
    is_allowed, status_code, message = defense_engine.inspect_request(
        client_ip=client_ip, 
        prompt=payload.prompt
    )

    if not is_allowed:
        raise HTTPException(status_code=status_code, detail=message)

    return {
        "status": status_code,
        "result": f"Model response generated for: '{payload.prompt}'"
    }

@app.get("/v1/security/metrics")
async def get_metrics():
    return defense_engine.metrics
