from database import SessionLocal, Vulnerabilities
from sqlalchemy import select

def get_CVEs_id()-> list[str]:
    with SessionLocal() as session:
        return session.execute(select(Vulnerabilities.cve_id)).scalars().all()
         
