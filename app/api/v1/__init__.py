from fastapi import APIRouter

from app.api.v1.routers import api_keys, audit, auth, orgs, projects, secrets, users

api_router = APIRouter(prefix="/api/v1")
for module in (auth, users, orgs, projects, secrets, api_keys, audit):
    api_router.include_router(module.router)
