import datetime
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Date, ForeignKey, Table, Boolean
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy_utils import database_exists, create_database

# Configuração do Banco de Dados
usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'CondoIQ'
url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}?charset=utf8mb4"

engine = create_engine(url, echo=True)
Session = sessionmaker(bind=engine)
Base = declarative_base()

reuniao_participantes = Table(
    'reuniao_participantes', Base.metadata,
    Column('usuario_id', Integer, ForeignKey('usuarios.id'), primary_key=True),
    Column('reuniao_id', Integer, ForeignKey('reunioes.id'), primary_key=True)
)

# Tipos atualizados
TIPO_SINDICO = 0
TIPO_PENDENTE = 1
TIPO_MORADOR = 2

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    tipo = Column(Integer, default=TIPO_PENDENTE)
    condominio_id = Column(Integer, ForeignKey("condominio.id"), nullable=True)
    is_ativo = Column(Boolean, default=True, nullable=False)

    condominio = relationship("Condominio", back_populates="usuarios")
    reunioes = relationship("Reuniao", secondary=reuniao_participantes, back_populates="participantes")

    def is_authenticated(self): return True
    def is_active(self): return self.is_ativo
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
    status = Column(String(50), default="pendente")
    usuarios = relationship("Usuario", back_populates="condominio")
    despesas = relationship("Despesa", back_populates="condominio")
    reunioes = relationship("Reuniao", back_populates="condominio")

class Despesa(Base):
    __tablename__ = "despesas"
    id = Column(Integer, primary_key=True)
    descricao = Column(String(255), nullable=False)
    valor = Column(Integer, nullable=False)
    data = Column(Date, nullable=False)
    categoria = Column(String(50), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"))
    condominio = relationship("Condominio", back_populates="despesas")

class Reuniao(Base):
    __tablename__ = "reunioes"
    id = Column(Integer, primary_key=True)
    titulo = Column(String(150), nullable=False)
    data = Column(Date, nullable=False)
    local = Column(String(255), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"))
    condominio = relationship("Condominio", back_populates="reunioes")
    participantes = relationship("Usuario", secondary=reuniao_participantes, back_populates="reunioes")

def criar_database_se_nao_existir():
    if not database_exists(engine.url):
        create_database(engine.url)

def criar_tabelas():
    Base.metadata.create_all(engine)

if __name__ == '__main__':
    criar_database_se_nao_existir()
    criar_tabelas()
    print("Banco de dados e tabelas criados com sucesso!")
