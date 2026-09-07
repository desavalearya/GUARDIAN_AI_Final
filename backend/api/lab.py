"""Model Lab endpoints. Scoring shares backend.detection.ml_runtime with live ingest."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from backend.detection import ml_runtime

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/lab", tags=["Model Lab"])


# ============================================================================
# Request/Response Models
# ============================================================================


class TextScanRequest(BaseModel):
    """Request to scan text for phishing"""
    text: str = Field(..., description="Text to analyze for phishing patterns")


class FileScanResponse(BaseModel):
    """Response from file/document scan"""
    filename: str
    file_type: str
    model_used: str
    model_version: str
    malicious_probability: float = Field(..., ge=0.0, le=1.0)
    verdict: str
    explanation: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    top_features: list[dict[str, Any]] = Field(default_factory=list)
    extracted_features: dict[str, float] = Field(default_factory=dict)
    analysis: dict[str, Any] = Field(default_factory=dict)


class TextScanResponse(BaseModel):
    """Response from text phishing scan"""
    text_preview: str
    model_used: str
    model_version: str
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    verdict: str
    explanation: str
    confidence: float = Field(..., ge=0.0, le=1.0)


# ============================================================================
# Model Loaders (Lazy Loading)
# ============================================================================


def _lab_verdict(verdict: str) -> str:
    return {
        "malicious": "MALICIOUS",
        "suspicious": "SUSPICIOUS",
        "clean": "CLEAN",
    }.get(verdict, verdict.upper())


# ============================================================================
# API Endpoints
# ============================================================================


@router.post("/scan/text", response_model=TextScanResponse)
async def scan_text(request: TextScanRequest) -> TextScanResponse:
    """
    Scan text for phishing patterns using XLM-RoBERTa model.
    
    **Use case**: Test email subject lines, message bodies, or any text.
    """
    import asyncio

    try:
        result = await asyncio.to_thread(ml_runtime.score_text, request.text)
        return TextScanResponse(
            text_preview=request.text[:100] + ("..." if len(request.text) > 100 else ""),
            model_used="XLM-RoBERTa",
            model_version=result.model_version,
            phishing_probability=result.phishing_probability,
            verdict=_lab_verdict(result.verdict),
            explanation=result.explanation,
            confidence=result.confidence,
        )
        
    except Exception as e:
        log.exception("Text scan failed")
        raise HTTPException(status_code=500, detail=f"Text scan failed: {str(e)}")


@router.post("/scan/office", response_model=FileScanResponse)
async def scan_office_document(file: UploadFile = File(...)) -> FileScanResponse:
    """
    Scan Office document (DOC, DOCX, XLS, XLSX, PPT, PPTX) for malware.
    
    **Use case**: Test Office files for malicious macros and VBA code.
    """
    import asyncio

    from backend.config import settings

    try:
        # Validate file type
        if not any(
            file.filename.lower().endswith(ext)
            for ext in [".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm"]
        ):
            raise HTTPException(status_code=400, detail="Only Office documents are supported")
        
        content = await file.read()
        if len(content) > settings.max_attachment_bytes:
            raise HTTPException(status_code=413, detail="File too large")
        result = await asyncio.to_thread(
            ml_runtime.score_office, content, file.filename or "document.docx"
        )
        return FileScanResponse(
            filename=file.filename or result.filename,
            file_type="Office Document",
            model_used="XGBoost",
            model_version=result.model_version,
            malicious_probability=result.malicious_probability,
            verdict=_lab_verdict(result.verdict),
            explanation=result.explanation,
            confidence=result.confidence,
            top_features=result.top_features,
            extracted_features=result.features,
            analysis=result.meta,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Office document scan failed")
        raise HTTPException(status_code=500, detail=f"Office scan failed: {str(e)}")


@router.post("/scan/pdf", response_model=FileScanResponse)
async def scan_pdf_document(file: UploadFile = File(...)) -> FileScanResponse:
    """
    Scan PDF document for malware.
    
    **Use case**: Test PDF files for malicious JavaScript, embedded files, etc.
    """
    import asyncio

    from backend.config import settings

    try:
        # Validate file type
        if not file.filename.lower().endswith('.pdf'):
            raise HTTPException(status_code=400, detail="Only PDF files are supported")
        
        content = await file.read()
        if len(content) > settings.max_attachment_bytes:
            raise HTTPException(status_code=413, detail="File too large")
        result = await asyncio.to_thread(
            ml_runtime.score_pdf, content, file.filename or "document.pdf"
        )
        return FileScanResponse(
            filename=file.filename or result.filename,
            file_type="PDF",
            model_used="Calibrated Random Forest",
            model_version=result.model_version,
            malicious_probability=result.malicious_probability,
            verdict=_lab_verdict(result.verdict),
            explanation=result.explanation,
            confidence=result.confidence,
            top_features=result.top_features,
            extracted_features=result.features,
            analysis=result.meta,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        log.exception("PDF scan failed")
        raise HTTPException(status_code=500, detail=f"PDF scan failed: {str(e)}")


@router.get("/models/status")
async def get_models_status():
    """Get status of all available models"""
    status = {
        "office_document": {
            "available": ml_runtime.model_path("doc", "office_malware_rf.joblib").exists(),
            "loaded": ml_runtime._office_model is not None,
            "type": "XGBoost",
            "version": "v1",
        },
        "pdf": {
            "available": (
                (ml_runtime.pdf_dir() / "pdf_malware_model.joblib").exists()
                or (ml_runtime.pdf_dir() / "pdf_malware_rf.joblib").exists()
            ),
            "loaded": ml_runtime._pdf_model is not None,
            "type": "Calibrated Random Forest",
            "version": "v3",
        },
        "email_text": {
            "available": (
                ml_runtime.model_path("email", "config.json").exists()
                and (
                    ml_runtime.model_path("email", "model.safetensors").exists()
                    or ml_runtime.model_path("email", "pytorch_model.bin").exists()
                )
            ),
            "loaded": ml_runtime._email_model is not None,
            "type": "XLM-RoBERTa",
            "version": "v1",
        },
        "url": {
            "available": (ml_runtime.model_path("url", "v1", "url_model.json").exists()),
            "loaded": False,
            "type": "XGBoost",
            "version": "url-xgb-v1",
            "note": "models/url/v1 active. Root models/url/* (except v1) remain parked.",
            "card_accuracy_pct": 89.73,
            "card_roc_auc": 0.9469,
        },
    }
    
    return status
