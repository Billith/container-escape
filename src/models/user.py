from database import Base
from sqlalchemy import Column, Integer, String, Boolean


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    login = Column(String(50), unique=True, nullable=False)
    password = Column(String(128), nullable=False)
    is_admin = Column(Boolean(), nullable=False)

    def __init__(self, login=None, password=None, is_admin=False):
        self.login = login
        self.password = password
        self.is_admin = is_admin

    def __repr__(self):
        return f'[ User {self.login} ]'
