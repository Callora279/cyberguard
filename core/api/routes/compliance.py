"""Compliance evidence-pack PDFs: NHS DSP Toolkit, GDPR Article 32, Cyber Essentials."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from core.api.middleware.auth import Principal, get_principal
from core.services.compliance import report_generator

router = APIRouter()


@router.get("/frameworks")
def frameworks() -> dict:
    return {"frameworks": report_generator.list_frameworks()}


@router.get("/report/{framework}")
def download_report(framework: str, principal: Principal = Depends(get_principal)) -> Response:
    pdf_bytes, filename = report_generator.generate(framework, principal.org_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
