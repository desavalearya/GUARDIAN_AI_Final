from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.auth import router as auth_router
from backend.api.health import router as health_router
from backend.api.ingest import router as ingest_router
from backend.api.lab import router as lab_router
from backend.api.mailbox import router as mailbox_router
from backend.api.cases import router as cases_router
from backend.api.soc import router as soc_router
from backend.api.tasks import router as tasks_router
from backend.config import settings
from backend.seed import seed_demo_users


@asynccontextmanager
async def lifespan(_app: FastAPI):
    seed_demo_users()
    yield


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(tasks_router)
app.include_router(ingest_router)
app.include_router(mailbox_router)
app.include_router(soc_router)
app.include_router(cases_router)
app.include_router(lab_router)
