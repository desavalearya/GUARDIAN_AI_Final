from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.database import get_db
from backend.models import CeleryPing, User
from backend.schemas import CeleryPingResponse, PingEnqueueResponse
from backend.workers.tasks import ping_db

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])


@router.post("/ping", response_model=PingEnqueueResponse)
def enqueue_ping(current_user: User = Depends(get_current_user)) -> PingEnqueueResponse:
    result = ping_db.delay(str(current_user.id))
    return PingEnqueueResponse(task_id=result.id)


@router.get("/pings", response_model=list[CeleryPingResponse])
def list_pings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CeleryPing]:
    del current_user
    return db.query(CeleryPing).order_by(CeleryPing.created_at.desc()).limit(50).all()
