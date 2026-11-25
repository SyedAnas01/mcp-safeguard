import httpx
import jwt


async def call_api(request, path):
    token = request.headers.get("Authorization")
    claims = jwt.decode(token.split()[1], KEY, algorithms=["RS256"], audience="https://mcp.example.com")
    down = await exchange_token(claims)
    async with httpx.AsyncClient() as c:
        return await c.get("https://api.example.com" + path, headers={"Authorization": down})
