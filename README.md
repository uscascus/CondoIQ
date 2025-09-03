# Guia de Configuração e Execução do Projeto

Este documento explica como configurar e executar a aplicação no seu ambiente local, garantindo que todas as dependências estejam corretamente instaladas e isoladas em um ambiente virtual.

---

### Passo 1: Configurar o Ambiente Virtual

É altamente recomendável usar um ambiente virtual para evitar conflitos de dependências com outras aplicações Python no seu sistema.

1.  **Crie o ambiente virtual:**
    ```bash
    python3 -m venv venv
    ```

2.  **Ative o ambiente virtual:**
    * **No Linux/macOS:**
        ```bash
        source venv/bin/activate
        ```
    * **No Windows:**
        ```bash
        venv\Scripts\activate
        ```

---

### Passo 2: Instalar as Dependências

Com o ambiente virtual ativado, instale todas as bibliotecas necessárias listadas no arquivo `requirements.txt`.

```bash
pip install -r requirements.txt

### Rodar o projeto!
python app.py

### Sair do ambiente virtual
deactivate

### Baixar as bibliotecas
pip freeze > requirements.txt

