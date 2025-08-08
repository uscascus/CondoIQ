import pymysql
from sqlalchemy import create_engine, Column, Integer, String, Text, Date, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

# Configurações do banco
usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'site_receitas'

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

receita_ingrediente = Table('receita_ingrediente', Base.metadata,
    Column('id_receita', Integer, ForeignKey('receita.id')),
    Column('id_ingrediente', Integer, ForeignKey('ingrediente.id')),
    Column('quantidade', String(100))
)

class Usuario(Base):
    __tablename__ = 'usuario'
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    data_cadastro = Column(Date, default=datetime.date.today)
    receitas = relationship('Receita', back_populates='autor')
    avaliacoes = relationship('Avaliacao', back_populates='usuario')
    favoritos = relationship('Favorito', back_populates='usuario')

class Receita(Base):
    __tablename__ = 'receita'
    id = Column(Integer, primary_key=True)
    titulo = Column(String(200), nullable=False)
    modo_preparo = Column(Text, nullable=False)
    tempo_preparo = Column(Integer)
    categoria = Column(String(100))
    imagem_url = Column(String(255))
    data_postagem = Column(Date, default=datetime.date.today)
    id_usuario = Column(Integer, ForeignKey('usuario.id'))
    autor = relationship('Usuario', back_populates='receitas')
    ingredientes = relationship('Ingrediente', secondary=receita_ingrediente, back_populates='receitas')
    avaliacoes = relationship('Avaliacao', back_populates='receita')

class Ingrediente(Base):
    __tablename__ = 'ingrediente'
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    receitas = relationship('Receita', secondary=receita_ingrediente, back_populates='ingredientes')

class Avaliacao(Base):
    __tablename__ = 'avaliacao'
    id = Column(Integer, primary_key=True)
    nota = Column(Integer, nullable=False)
    comentario = Column(Text)
    data_avaliacao = Column(Date, default=datetime.date.today)
    id_usuario = Column(Integer, ForeignKey('usuario.id'))
    id_receita = Column(Integer, ForeignKey('receita.id'))
    usuario = relationship('Usuario', back_populates='avaliacoes')
    receita = relationship('Receita', back_populates='avaliacoes')

class Favorito(Base):
    __tablename__ = 'favorito'
    id = Column(Integer, primary_key=True)
    id_usuario = Column(Integer, ForeignKey('usuario.id'))
    id_receita = Column(Integer, ForeignKey('receita.id'))
    usuario = relationship('Usuario', back_populates='favoritos')
    receita = relationship('Receita')

def criar_tabelas():
    url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}"
    engine = create_engine(url, echo=True)
    Base.metadata.create_all(engine)
    print("Tabelas criadas com sucesso no banco MySQL.")

if __name__ == "__main__":
    criar_database_se_nao_existir()
    criar_tabelas()
