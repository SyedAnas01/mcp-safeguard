import httpx


async def call_api(request, path):
    token = request.headers.get("Authorization")
    async with httpx.AsyncClient() as c:
        return await c.get("https://api.example.com" + path, headers={"Authorization": token})
