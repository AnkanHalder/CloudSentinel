from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import relationship

from ..database import Base


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    file_type = Column(String)  # e.g., 'terraform', 'cloudformation'
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String)  # 'completed', 'failed'

    vulnerabilities = relationship("Vulnerability", back_populates="audit_record")
