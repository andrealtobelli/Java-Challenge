# 🚀 TrackZone - Gestão de Motos em Pátios

**TrackZone** é uma API REST desenvolvida em Java com Spring Boot para auxiliar no gerenciamento de motos em pátios de filiais. A solução foi pensada para facilitar o controle de check-in, check-out, status, localização e histórico das motos, oferecendo também uma visualização inteligente e otimizada do pátio.

---

## 🧱 Tecnologias Utilizadas

- Java 17+
- Spring Boot 3+
- Spring Web
- Spring Data JPA
- Spring Security
- Spring Cache
- Bean Validation (Jakarta)
- H2 Database
- Swagger/OpenAPI (Springdoc)
- Maven

---

## 🧩 Funcionalidades

- ✅ Login e cadastro de filial
- ✅ Cadastro de motos com informações detalhadas
- ✅ Check-in e check-out de motos
- ✅ Atualização de status da moto (em manutenção, pronta para alugar, etc.)
- ✅ Página inicial com resumo da operação (dashboard)
- ✅ Mapa do pátio com localização por plano cartesiano
- ✅ Filtros por status, placa e data
- ✅ Paginação e ordenação dos resultados
- ✅ Documentação automática com Swagger
- ✅ Cache para otimizar requisições
- ✅ Boas práticas REST e tratamento centralizado de erros

---

## 🔒 Acesso e Segurança

- A API utiliza **Spring Security** com autenticação básica (`HTTP Basic Auth`)
- Usuário padrão:  
  - **Login:** `admin`  
  - **Senha:** `1234`

---

## 📑 Documentação da API

Acesse a documentação interativa:

🔗 [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)  
ou  
🔗 [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html)

---

## ▶️ Como Executar o Projeto

1. Clone este repositório:
   ```bash
   git clone https://github.com/SeuUsuario/trackzone.git
   cd trackzone
   
2. Abra no Eclipse ou IntelliJ com suporte a Maven.

3. Execute a classe principal:
```
  JavaApplication.java
```
4. Acesse o Swagger ou utilize ferramentas como Postman.

- http://localhost:8080/swagger-ui/index.html#/

5. Exemplo de como testar os endpoints

/filiais/login

{
  "email": "central@trackzone.com",
  "senha": "123456"
}

---------------------------------------
/filiais/cadastro

{
  "nome": "Filial Central",
  "email": "central@trackzone.com",
  "senha": "123456"
}

------------------------------------
dashboard/filialId

1

---------------------------------------
/motos/atualizar/id

1

{
  "placa": "ABC-1234",
  "chassi": "9BWZZZ377VT004251",
  "motor": "MTR-98765",
  "status": "Disponível",
  "localizacao": "A3"
}

---------------------------------------
motos/inserir

{
  "placa": "ABC-1234",
  "chassi": "9BWZZZ377VT004251",
  "motor": "MTR-98765",
  "status": "Disponível",
  "localizacao": "A2"
}

-----------------------------------------
/motos/id

1

-------------------------------------------
/motos/todas_cacheable

execute

-----------------------------------------
/motos/status

Disponível

0

5

-----------------------------------------
/motos/paginadas

0

5

----------------------------------------
/motos/remover/id

1
---

## 🗃️ Banco de Dados

- Utiliza banco em memória H2 para facilitar os testes.
- Acesse o console do H2:
```
  http://localhost:8080/h2-console
```
- JDBC URL: jdbc:h2:mem:testdb
- Usuário: sa
- Senha: (deixe em branco)

---

## 📁 Estrutura de Pacotes
```
  trackzone/
  ├── config/
  ├── controller/
  ├── dto/
  ├── exception/
  ├── model/
  ├── projection/
  ├── repository/
  ├── security/
  ├── service/
  ├── swagger/

```

---

## 📄 Endpoints principais

```
| Método | Endpoint               | Descrição                                |
| ------ | ---------------------- | ---------------------------------------- |
| POST   | /filiais/login         | Logar na conta                           |
| POST   | /filiais/cadastro      | Cadastrar nova conta                     |
| GET    | /dashboard/filialId    | Lista a filial pelo ID                   |
| PUT    | /motos/atualizar/{id}  | Atualiza moto por ID                     |
| POST   | /motos/inserir         | Cadastra nova moto                       |
| GET    | /motos/id              | Lista moto por id                        |
| GET    | /motos/todas_cacheable | Mostra motos em cache                    |
| GET    | /motos/status          | Filtra motos por status                  |
| GET    | /motos/paginadas       | Lista paginada de motos                  |
| DELETE | /motos/remover/{id}    | Remove moto por ID                       |

```
- |⚠️ Todos os endpoints (exceto públicos) requerem autenticação básica.

---

## 📌 Observações

- Projeto desenvolvido para o Challenge da FIAP.
- Foco em boas práticas REST, separação por camadas, documentação e validação.
- Swagger e console H2 facilitam testes rápidos e visualização da estrutura da aplicação.

---

## 📄 Licença
- Projeto acadêmico para uso em contexto educacional, todos os direitos reservados.
- © 2025 – Leticia Cristina Dos Santos Passos

## 👥 Desenvolvedores

- Leticia Cristina Dos Santos Passos RM: 555241
- André Rogério Vieira Pavanela Altobelli Antunes RM: 554764
- Enrico Figueiredo Del Guerra RM: 558604








