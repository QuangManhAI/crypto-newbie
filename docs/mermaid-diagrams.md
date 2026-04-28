# Mermaid Diagrams

## 1) AES-128 CTR Flow

```mermaid
%%{init: {'themeVariables': {'fontSize': '60px'}, 'flowchart': {'nodeSpacing': 60, 'rankSpacing': 50, 'padding': 36, 'curve': 'basis'}}}%%
flowchart LR
    A[Input key plaintext and nonce-counter]
    B[Key expansion]
    C[Split plaintext to blocks]
    D[Encrypt nonce+counter with AES core]
    E[Generate keystream block]
    F[XOR plaintext block with keystream]
    G[Ciphertext block]
    H[Increment counter]
    I{More blocks}
    J[Join ciphertext blocks]

    A --> B
    A --> C
    B --> D
    C --> F
    D --> E --> F --> G --> H --> I
    I -- Yes --> D
    I -- No --> J
```

## 1.1) CTR Block Diagram

```mermaid
%%{init: {'themeVariables': {'fontSize': '34px'}, 'flowchart': {'nodeSpacing': 110, 'rankSpacing': 96, 'padding': 48, 'curve': 'linear'}}}%%
flowchart LR
    subgraph ENC[CTR Encryption lane]
        direction LR
        P[Pi plaintext block]
        N[Nonce]
        CTR[Counter i]
        NC[Build input block from Nonce and Counter i]
        A[AES Encrypt with key K]
        S[Si keystream block]
        X[XOR]
        C[Ci ciphertext block]
        INC[Increment counter to i+1]

        N --> NC
        CTR --> NC --> A --> S --> X --> C --> INC
        P --> X
    end

    subgraph DEC[CTR Decryption lane]
        direction LR
        CC[Ci ciphertext block]
        NN[Nonce]
        CCTR[Counter i]
        NNC[Build input block from Nonce and Counter i]
        AA[AES Encrypt with key K]
        SS[Si keystream block]
        XX[XOR]
        PP[Pi plaintext block]

        NN --> NNC
        CCTR --> NNC --> AA --> SS --> XX --> PP
        CC --> XX
    end

    INC -. next block .-> CCTR
```

## 2) ECC Flow (Key Generation)

```mermaid
%%{init: {'themeVariables': {'fontSize': '60px'}, 'flowchart': {'nodeSpacing': 60, 'rankSpacing': 50, 'padding': 36, 'curve': 'basis'}}}%%
flowchart LR
    A[MSSV and full name] --> B[SHA-256 seed]
    B --> C[Build curve p a b]
    C --> D[Find generator G and order n]
    D --> E[Derive private key d]
    E --> F[Compute public key Q]
    F --> G[Validate Q on curve]
    G --> H[Output curve d Q]
```

## 3) SHA-256 Flow

```mermaid
%%{init: {'themeVariables': {'fontSize': '60px'}, 'flowchart': {'nodeSpacing': 60, 'rankSpacing': 50, 'padding': 36, 'curve': 'basis'}}}%%
flowchart LR
    A[Input message] --> B[Preprocess and padding]
    B --> C[Split into 512-bit blocks]
    C --> D[Prepare W0 to W63]
    D --> E[Initialize a to h]
    E --> F[Run 64 rounds]
    F --> G[Update H0 to H7]
    G --> H{More blocks}
    H -- Yes --> D
    H -- No --> I[Concatenate H words]
    I --> J[Output digest hex]
```

## 4) Schnorr Signature Flow

```mermaid
%%{init: {'themeVariables': {'fontSize': '60px'}, 'flowchart': {'nodeSpacing': 60, 'rankSpacing': 50, 'padding': 36, 'curve': 'basis'}}}%%
flowchart LR
    A[Input curve keys and message] --> B[Nonce k]
    B --> C[Compute R equals kG]
    C --> D[Compute e from hash]
    D --> E[Compute s mod n]
    E --> F[Signature e s]
    F --> G[Compute R prime]
    G --> H[Compute e prime]
    H --> I{e prime equals e}
    I -- True --> J[Valid signature]
    I -- False --> K[Invalid signature]
```

## Optional: System Integration (4 Algorithms)

```mermaid
%%{init: {'themeVariables': {'fontSize': '24px'}, 'flowchart': {'nodeSpacing': 44, 'rankSpacing': 36, 'padding': 16, 'curve': 'basis'}}}%%
flowchart LR
    A[ECC or ECDH] --> B[Session key] --> C[AES encrypt data] --> H[Ciphertext] --> I[Receiver decrypt]
    D[Message] --> E[SHA-256 digest] --> J[Receiver verify]
    D --> F[Schnorr sign] --> G[Signature] --> J
```

## 5) System Architecture (From Image)

```mermaid
%%{init: {'themeVariables': {'fontSize': '34px'}, 'flowchart': {'nodeSpacing': 186, 'rankSpacing': 182, 'padding': 36, 'curve': 'linear'}}}%%
flowchart TB
    subgraph CLIENT[CLIENT LAYER]
        direction LR
        WEB[Web App\nReact Next]
        MOBILE[Mobile App\nReact Native]
        THIRD[Third-Party Client\nREST API SDK]
    end

    APIGW[API GATEWAY\nNode.js Express]
    GWFUNC[Rate Limiting, JWT Validation, Request Routing, CORS]

    subgraph SERVICE[SERVICE LAYER]
        direction LR
        AUTH[Auth Service\nJWT MFA RBAC]
        RENTAL[Rental Service\nProperty Tenant Contract]
        BILLING[Billing Service\nInvoice Payment Gateway]
        AI[AI Agent Service\nLLM RAG NLP ML]
    end

    NOTI[Notification Service\nSMTP FCM Twilio Zalo]

    subgraph DATAINFRA[DATA and INFRASTRUCTURE LAYER]
        direction LR
        PG[(PostgreSQL\nPrimary DB)]
        REDIS[(Redis\nCache + Sessions)]
        ES[(Elasticsearch\nFull-text Search + Log Aggregation)]
    end

    subgraph EXTINFRA[EXTENDED INFRA COMPONENTS]
        direction LR
        S3[(Amazon S3\nFile Storage)]
        MQ[(RabbitMQ\nKafka MQ)]
        TS[(TimescaleDB\nTime-Series Analytics)]
    end

    WEB --> APIGW
    MOBILE --> APIGW
    THIRD --> APIGW

    APIGW --> GWFUNC
    GWFUNC --> AUTH
    GWFUNC --> RENTAL
    GWFUNC --> BILLING
    GWFUNC --> AI

    AUTH --> NOTI
    RENTAL --> NOTI
    BILLING --> NOTI
    AI --> NOTI

    AUTH --> PG
    RENTAL --> PG
    BILLING --> PG

    AUTH --> REDIS
    RENTAL --> REDIS
    BILLING --> REDIS
    AI --> REDIS

    AUTH --> ES
    RENTAL --> ES
    BILLING --> ES
    AI --> ES

    RENTAL --> S3
    BILLING --> MQ
    AI --> TS
```
