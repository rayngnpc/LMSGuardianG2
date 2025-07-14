from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List
from app.database.database import getDb
from app.schemas import scrapedContent as schemas
from app.crud import scrapedContent as crud

router = APIRouter(prefix="/scrapedcontents", tags=["Scraped Contents"])


@router.get("/", response_model=List[schemas.ScrapedContent])
def get_all_scraped_contents(db: Session = Depends(getDb)):
    return crud.getAll(db)


@router.get("/testroute/", response_model=List[schemas.ScrapedContent])
def get_all_scraped_contents(db: Session = Depends(getDb)):
    return crud.getAll(db)


@router.post("/", response_model=schemas.ScrapedContent)
def create_scraped_content(
    item: schemas.ScrapedContentCreate, db: Session = Depends(getDb)
):
    return crud.create_scraped_content(db, item)


@router.get("/scan", response_model=List[schemas.ScrapedContent])
def get_high_risks(db: Session = Depends(getDb)):
    return crud.getRecentScan(db)


@router.get("/highrisks", response_model=List[schemas.ScrapedContent])
def get_negative_risks(db: Session = Depends(getDb)):
    return crud.getDangerousLinks(db)


@router.get("/safe", response_model=List[schemas.ScrapedContent])
def get_safe_links(db: Session = Depends(getDb)):
    return crud.get_safe_to_download(db)


@router.get("/localcopyavailable/{module_id}")
def get_local_copies_by_module(module_id: int, db: Session = Depends(getDb)):
    return crud.get_localcopies_by_module(db, module_id)


@router.put("/updaterisk/{link_id}")
def update_risk_info_api(
    link_id: int, score: float, category: str, db: Session = Depends(getDb)
):
    rows_updated = crud.update_risk_info(db, link_id, score, category)
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Link not found")
    return {
        "message": "Risk info updated",
        "link_id": link_id,
        "new_score": score,
        "new_category": category,
    }


@router.put("/updatepaywall/{link_id}")
def updatepaywall(link_id: int, ispaywall: bool, db: Session = Depends(getDb)):
    rows_updated = crud.updatePaywallStatus(db, link_id, ispaywall)
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"message": "Risk info updated", "link_id": link_id, "is_paywall": ispaywall}


@router.put("/updatecitation/{link_id}")
def updatecitation(link_id: int, citation: str, db: Session = Depends(getDb)):
    rows_updated = crud.updateAPA7citation(db, link_id, citation)
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"message": "Risk info updated", "link_id": link_id, "apa7": citation}


@router.put("/localurl/{scraped_id}")
def update_localurl_route(scraped_id: int, localurl: str, db: Session = Depends(getDb)):
    updated = crud.update_localurl(db, scraped_id, localurl)
    if updated == 0:
        raise HTTPException(status_code=404, detail="scraped_id not found")

    return {
        "scraped_id": scraped_id,
        "localurl": localurl,
        "message": "localurl updated",
    }
