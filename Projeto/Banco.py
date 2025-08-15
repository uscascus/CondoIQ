import pymysql
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

# Configurações do banco
usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'condominio_comunidade'

# Conecta ao MySQL para criar o banco, se necessário
def criar_database_se_nao_existir():
    conexao = pymysql.connect(host=host, user=usuario, password=senha)
    cursor = conexao.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {banco} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    conexao.commit()
    cursor.close()
    conexao.close()
    print(f"Database `{banco}` verificado/criado com sucesso.")

# ORM - SQLAlchemy
Base = declarative_base()

# Associação para participação em reuniões
participacao_reuniao = Table('participacao_reuniao', Base.metadata,
    Column('id_reuniao', Integer, ForeignKey('reuniao.id')),
    Column('id_usuario', Integer, ForeignKey('usuario.id')),
    Column('presente', Boolean, default=False)
)

class Usuario(Base):
    __tablename__ = 'usuario'
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    tipo = Column(String(50))  # morador ou sindico
    telefone = Column(String(20))
    data_cadastro = Column(DateTime, default=datetime.datetime.now)
    
    despesas = relationship('Despesa', back_populates='responsavel')
    mensagens_enviadas = relationship('Mensagem', back_populates='remetente')
    reunioes = relationship('Reuniao', secondary=participacao_reuniao, back_populates='participantes')

class Despesa(Base):
    __tablename__ = 'despesa'
    id = Column(Integer, primary_key=True)
    descricao = Column(String(200), nullable=False)
    valor = Column(Integer, nullable=False)
    data = Column(DateTime, default=datetime.datetime.now)
    tipo = Column(String(50))
    id_responsavel = Column(Integer, ForeignKey('usuario.id'))
    
    responsavel = relationship('Usuario', back_populates='despesas')

class Reuniao(Base):
    __tablename__ = 'reuniao'
    id = Column(Integer, primary_key=True)
    titulo = Column(String(200), nullable=False)
    data_hora = Column(DateTime, nullable=False)
    local = Column(String(100))
    descricao = Column(Text)
    status = Column(String(50))  # agendada, realizada, cancelada
    
    participantes = relationship('Usuario', secondary=participacao_reuniao, back_populates='reunioes')

class Mensagem(Base):
    __tablename__ = 'mensagem'
    id = Column(Integer, primary_key=True)
    conteudo = Column(Text, nullable=False)
    data_envio = Column(DateTime, default=datetime.datetime.now)
    id_remetente = Column(Integer, ForeignKey('usuario.id'))
    id_destinatario = Column(Integer, ForeignKey('usuario.id'), nullable=True)  # NULL para mensagem geral
    
    remetente = relationship('Usuario', back_populates='mensagens_enviadas')

def criar_tabelas():
    url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}"
    engine = create_engine(url, echo=True)
    Base.metadata.create_all(engine)
    print("Tabelas criadas com sucesso no banco MySQL.")

if __name__ == "__main__":
    criar_database_se_nao_existir()
    criar_tabelas()
