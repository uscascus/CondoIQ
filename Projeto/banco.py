import datetime
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Date, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy_utils import database_exists, create_database

usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'CondoIQ'
url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}?charset=utf8mb4"

engine = create_engine(url, echo=True)
Session = sessionmaker(bind=engine)

Base = declarative_base()

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    tipo = Column(String(50), default="condomino")
    condominio_id = Column(Integer, ForeignKey("condominio.id"), nullable=True)
    verification_code = Column(String(10), nullable=True)  # nova coluna

    condominio = relationship("Condominio", back_populates="usuarios")

    # Flask-Login
    def is_authenticated(self): return True
    def is_active(self): return True
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)


class Condominio(Base):
    __tablename__ = "condominio"
    id = Column(Integer, primary_key=True)
    nome = Column(String(150), nullable=False)
    endereco = Column(String(255), nullable=False)
    cnpj = Column(String(18), unique=True, nullable=True)
    telefone = Column(String(20), nullable=True)
    email = Column(String(100), nullable=True)
    data_cadastro = Column(Date, default=datetime.date.today)
    status = Column(String(50), default="pendente")  # começa como pendente
    usuarios = relationship("Usuario", back_populates="condominio")

def criar_database_se_nao_existir():
    if not database_exists(engine.url):
        create_database(engine.url)

def criar_tabelas():
    Base.metadata.create_all(engine)
