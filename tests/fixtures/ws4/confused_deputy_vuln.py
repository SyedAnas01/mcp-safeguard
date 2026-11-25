import os
from starlette.responses import RedirectResponse

UPSTREAM_CLIENT_ID = os.environ["UPSTREAM_CLIENT_ID"]


async def register(request):
    body = await request.json()
    return {"client_id": new_id(), "redirect_uris": body["redirect_uris"]}


async def authorize(request):
    state = new_state()
    return RedirectResponse(
        f"https://idp.example.com/authorize?client_id={UPSTREAM_CLIENT_ID}&state={state}"
    )

routes = [Route("/register", register), Route("/authorize", authorize)]
