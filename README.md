# Verificador de E-mails Temporários (API)

Esta API permite verificar se um endereço de e-mail pertence a um provedor de e-mail temporário (descartável). Ela utiliza múltiplas listas de bloqueio do GitHub e verifica os registros MX do domínio para garantir uma validação precisa.

## 🚀 Como Funciona

1.  **Verificação de Sintaxe**: Valida se o formato do e-mail é correto.
2.  **Verificação em Listas de Bloqueio**: Consulta o domínio em 3 listas colaborativas (atualizadas a cada 24h).
3.  **Verificação de DNS MX**: Confirma se o domínio possui servidores de e-mail configurados e ativos.
4.  **Pontuação (Score)**: Retorna um score de confiança (0 ou 100).

---

## 🛠️ Como Usar

### 1. Instalação e Execução

Instale as dependências e inicie o servidor:

```bash
npm install
npm start
# O servidor rodará em http://localhost:3000
```

### 2. Fazendo uma Consulta

Para verificar um e-mail, faça uma requisição `GET` para o endpoint `/verify`:

**Endpoint:**
`GET http://localhost:3000/verify?email={email_a_verificar}`

**Exemplo (cURL):**
```bash
curl "http://localhost:3000/verify?email=teste@mailinator.com"
```

**Exemplo (JavaScript/Node):**
```javascript
const response = await fetch('http://localhost:3000/verify?email=usuario@gmail.com');
const data = await response.json();
console.log(data);
```

---

## 📄 Resposta Esperada

A API retorna um objeto JSON com os detalhes da verificação.

**Exemplo de E-mail Válido:**
```json
{
  "email": "usuario@gmail.com",
  "domain": "gmail.com",
  "isValidSyntax": true,
  "isDisposable": false,
  "hasMxRecords": true,
  "score": 100,
  "reasons": [
    "Domain is valid and has MX records"
  ]
}
```

**Exemplo de E-mail Temporário:**
```json
{
  "email": "teste@mailinator.com",
  "domain": "mailinator.com",
  "isValidSyntax": true,
  "isDisposable": true,
  "hasMxRecords": true,
  "score": 0,
  "reasons": [
    "Domain is in disposable email blocklist"
  ]
}
```

---

## 📊 Tabela de Pontuação (Score)

| Score | Significado | Ação Recomendada |
| :--- | :--- | :--- |
| **100** | **E-mail Confiável** | ✅ Permitir cadastro. O domínio não está em listas negras e possui registros MX válidos. |
| **0** | **E-mail Inválido ou Temporário** | ❌ Bloquear cadastro. O domínio é conhecido por ser temporário, ou não possui registros MX, ou a sintaxe é inválida. |

### Detalhamento dos Critérios de Score 0:
- **Domain is in disposable email blocklist**: O domínio foi encontrado em uma das listas de e-mails descartáveis.
- **Domain has no valid MX records**: O domínio existe, mas não está configurado para receber e-mails (provavelmente fake).
- **Invalid email syntax**: O formato do e-mail está incorreto (ex: falta `@`).
