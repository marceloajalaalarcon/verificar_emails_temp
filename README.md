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

**Exemplo (cURL no CMD ou Bash):**
```bash
curl "http://localhost:3000/verify?email=teste@mailinator.com"
```

**Exemplo (PowerShell):**
No PowerShell, use `Invoke-RestMethod` ou `curl.exe`:
```powershell
# Opção 1 (Recomendada):
Invoke-RestMethod -Uri "http://localhost:3000/verify?email=teste@mailinator.com"

# Opção 2 (cURL nativo):
curl.exe "http://localhost:3000/verify?email=teste@mailinator.com"
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

## 📊 Tabela de Pontuação (Deep Check)

A API utiliza uma abordagem em **duas fases** para maximizar a segurança.

### Fase 1: O "Paredão" (Bloqueio Imediato)
Se o domínio estiver em uma das nossas listas negras (ex: `temp-mail.org`, `mailinator.com`), o e-mail recebe **Score 0** imediatamente e é bloqueado. Não há processamento adicional.

### Fase 2: Análise Profunda (0 a 100 pontos)
Se o domínio for desconhecido ou legítimo, aplicamos os critérios abaixo:

| Critério | Pontos | Descrição |
| :--- | :--- | :--- |
| **Não Descartável** | **+30** | O domínio sobreviveu à Fase 1. |
| **Caixa de Entrada (SMTP)** | **+30** | Conectamos ao servidor (Porta 25) e confirmamos que usuário existe. |
| **Registros MX** | **+20** | O domínio tem servidores de e-mail configurados. |
| **Sintaxe Válida** | **+10** | Formato básico correto. |
| **E-mail Pessoal** | **+5** | Não é um e-mail genérico como `admin@` ou `suporte@`. |
| **Legibilidade** | **+5** | O usuário não parece ser aleatório (ex: `a1b2c3d4`). |

---

### Classificação Final:

| Score | Status | Ação |
| :--- | :--- | :--- |
| **100** | **Perfeito** | ✅ E-mail 100% validado e existente. |
| **70 - 95** | **Seguro** | ✅ Provavelmente um e-mail corporativo ou com bloqueio de SMTP. Aceitável. |
| **40 - 65** | **Suspeito** | ⚠️ Domínio existe, mas o usuário não foi encontrado ou o e-mail é genérico/estranho. |
| **< 40** | **Lixo** | ❌ Bloquear. Domínio sem MX ou erro grave. |

### Exemplo de Resposta (Deep Check):
```json
{
  "email": "dev@google.com",
  "score": 100,
  "reasons": [
    "Valid Syntax (+10)",
    "Domain Trusted (Not in Blocklist) (+30)",
    "MX Records Valid (+20)",
    "Personal Address (Not Role-Based) (+5)",
    "User looks legitimate (Not Gibberish) (+5)",
    "SMTP Handshake: Mailbox Exists (+30)"
  ]
}
```

