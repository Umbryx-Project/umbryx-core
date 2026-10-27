from sqlalchemy import Column, Integer, String

from ..database import Base


class ProjectEncryptionKey(Base):
    __tablename__ = "project_encryption_keys"

    project_id = Column(String, primary_key=True)
    dek_enc = Column(String, nullable=False)
    algorithm = Column(String, nullable=False, default="fernet-aes128")
    created_at = Column(String, nullable=False)
    rotated_at = Column(String, nullable=True)
    version = Column(Integer, nullable=False, default=1)
