# Architecture Design

## System Architecture Overview

FastAPI Backend It adopts a classic three-tier architecture design to ensure the maintainability, scalability and testability of the code.

```mermaid
flowchart TD
    subgraph Clients [Clients]
        WEB[Web Browser]
        MOB[Mobile App]
        DESK[Desktop Client]
    end
 
    subgraph Gateway [API Gateway Layer]
        direction LR
        GW[API Gateway]
        AUTH[Authentication]
        RATE[Rate Limiting]
        LOG[Logging]
        CACHE[Cache Layer]
    end
 
    subgraph Modules [Backend Modules]
        subgraph UserModule [User Module]
            direction TB
            U_HTTP[HTTP Logic]
            U_BUSINESS[Business Logic]
            U_DATA[Data Access]
            U_ENTITY[Data Entity]
        end
       
        subgraph RoleModule [Role Module]
            direction TB
            P_HTTP[HTTP Logic]
            P_BUSINESS[Business Logic]
            P_DATA[Data Access]
            P_ENTITY[Data Entity]
        end
    end
 
    subgraph Databases [Databases]
        USER_DB[(User DB)]
        ROLE_DB[(Role DB)]
    end
 
    Clients --> Gateway
    Gateway --> U_HTTP
    Gateway --> P_HTTP
   
    U_HTTP --> U_BUSINESS --> U_DATA --> U_ENTITY --> USER_DB
    P_HTTP --> P_BUSINESS --> P_DATA --> P_ENTITY --> ROLE_DB
```

## Core design principles

### 1. Single Responsibility Principle

Each level has clear responsibilities to avoid confusion of responsibilities:

- **Controller Layer**: Handling HTTP requests and responses
- **Service Layer**: Implementing business logic
- **Repository Layer**: Data access and persistence
- **Entity Layer**: Data structure definition

### 2. Dependency Inversion Principle

High-level modules do not depend on low-level modules and are decoupled through interfaces:

```python
# The Service layer relies on the Repository abstraction
class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
```

### 3. Open/Closed Principle

Open for extension, closed for modification:

```python
# Extending functionality through inheritance
class EnhancedUserService(UserService):
    def create_user_with_notification(self, user_data):
        user = super().create_user(user_data)
        self.send_notification(user)
        return user
```

## Detailed explanation of hierarchical architecture

### Controller layer (src/module/[name]/controller)

Responsible for processing HTTP requests and responses, including:

- **Route Definition**: Defining API endpoints
- **Request Verification**: Validating input parameters
- **Response Formatting**: Unified response format
- **Exception handling**: Unified error handling

```python
@router.post("/users", response_model=UserResponse)
async def create_user(user_data: UserCreate):
    """Create a user API endpoint"""
    return await user_service.create_user(user_data)
```

### Service layer (src/module/[name]/service/)

Contains core business logic, including:

- **Business Rules**: Implementing business logic
- **Permission Verification**: Check User Permissions
- **Transaction Management**: Coordinating multiple operations
- **Cache Management**: Data caching strategy

```python
class UserService:
    async def create_user(self, user_data: UserCreate):
        # Business logic verification
        if await self.user_repo.exists(email=user_data.email):
            raise ValueError("Email already exists")

        # Password encryption
        user_data.password = hash_password(user_data.password)

        # Create a User
        return await self.user_repo.create(user_data)
```

### Repository Layer (src/module/[name]/repository/)

Responsible for data access, including:

- **CRUD operations**: Basic data operations
- **Query Building**: Complex query building
- **Data Mapping**: Model and DTO conversion
- **Transaction Control**: Database transaction management

```python
class UserRepository:
    async def create(self, user_data: UserCreate) -> User:
        return await User.create(**user_data.dict())

    async def get_by_id(self, user_id: int) -> Optional[User]:
        return await User.get_or_none(id=user_id)
```

### Entity layer (src/module/[name]/entity/)

Define the data structure, including:

- **Data Model**: Tortoise ORM Model
- **Relationship Definition**: Configuration of relationships between tables
- **Index Configuration**: Database index
- **Constraint Definition**: Data constraints

```python
class User(EntityBase, TimestampMixin):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True)
    email = fields.CharField(max_length=100, unique=True)

    # Relationship Definition
    roles = fields.ManyToManyField("models.Role", related_name="users")
```

## Core Components

### 1. CSRF protection

CSRF Token in SPA (Single Page Application) mechanism:

```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant S as Server/API
    participant A as Auth Service

    Note over U,S: Initial App Load
    U->>B: Open SPA
    B->>S: GET /api/csrf-token
    S->>A: Generate CSRF Token
    A-->>S: Token: csrf_xyz789
    S-->>B: 200 OK + {csrfToken: "csrf_xyz789"}<br/>Set-Cookie: csrf_token=csrf_xyz789
    B->>B: Store token in memory

    Note over U,S: API Request với CSRF Protection
    U->>B: Trigger API call (e.g., update profile)
    B->>S: POST /api/user/profile<br/>X-CSRF-Token: csrf_xyz789<br/>Cookie: csrf_token=csrf_xyz789
    S->>A: Validate CSRF Token
    A-->>S: Token Valid
    S->>S: Process Request
    S-->>B: 200 OK + Updated Data
    B->>U: Update UI
```

CSRF Attack Prevention mechanism:

```mermaid
sequenceDiagram
    participant V as Victim User
    participant VB as Victim Browser
    participant A as Attacker
    participant AS as Attacker Server
    participant LS as Legitimate Server

    Note over V,LS: Legitimate Flow
    V->>VB: Login to bank.com
    VB->>LS: GET bank.com/transfer
    LS-->>VB: 200 OK + CSRF Token<br/>Set-Cookie: csrf_token=legit123

    Note over A,LS: Attack Flow
    A->>AS: Host malicious page
    V->>VB: Visit attacker.com (while logged into bank.com)
    VB->>AS: GET attacker.com/malicious-form
    AS-->>VB: HTML with auto-submit form to bank.com

    Note over VB,LS: CSRF Protection in Action
    VB->>LS: POST bank.com/transfer<br/>Cookie: csrf_token=legit123<br/>Body: to_account=attacker&amount=1000<br/>BUT NO CSRF TOKEN IN BODY!
    LS->>LS: Validate CSRF Token → FAIL!
    LS-->>VB: 403 Forbidden<br/>CSRF Token Missing/Invalid
    VB->>V: Show Error Message
```

### 2. Authentication system

JWT-based authentication mechanism:

```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant S as Server
    participant DB as Database

    Note over U,DB: End-to-End Secure Authentication

    U->>B: Access application
    B->>S: GET /
    S-->>B: 200 OK + Login page

    U->>B: Login with credentials
    B->>S: POST /auth/login (with CSRF protection)
    S->>DB: Validate credentials & create session
    S-->>B: Set HttpOnly JWT cookie + redirect

    loop Active Session
        B->>S: API requests with JWT cookie
        S->>DB: Validate session on each request
        S-->>B: Responses with data
    end

    U->>B: Logout explicitly
    B->>S: POST /auth/logout
    S->>DB: Invalidate session
    S-->>B: Clear cookies + redirect

    Note over U,DB: OR Session Timeout
    S->>DB: Auto-cleanup expired sessions
    B->>S: Request with expired session
    S-->>B: 401 + Clear cookies
```

### 3. Permission Control

RBAC-based permission mechanism:

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client
    participant M as Middleware
    participant RBAC as RBAC Service
    participant DB as Database
    participant S as Service

    Note over U,S: End-to-End RBAC Authorization
    
    U->>C: Request action
    C->>M: HTTP Request + JWT
    
    M->>M: 1. Authenticate JWT
    M->>M: 2. Extract user/roles from token
    
    M->>RBAC: authorize(user_id, roles, action, resource)
    
    RBAC->>DB: 3. Get user permissions (roles + overrides)
    DB-->>RBAC: Combined permissions
    
    RBAC->>RBAC: 4. Evaluate permission logic
    RBAC->>RBAC: 5. Check resource context if needed
    RBAC->>RBAC: 6. Apply hierarchical rules
    
    alt Permission Granted
        RBAC-->>M: Authorization: GRANTED
        M->>S: Forward request
        S-->>M: Business logic result
        M-->>C: 200 OK + Data
        C->>U: Success
    else Permission Denied
        RBAC-->>M: Authorization: DENIED
        M-->>C: 403 Forbidden
        C->>U: Access denied
    end
```

### 4. Database design

Use Tortoise ORM to implement data persistence:

```mermaid
erDiagram
    T_USERS {
        uuid id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at

        varchar(20) username
        varchar(128) password_hash
        varchar(255) full_name
        varchar(255) email
        varchar(20) tel
        text description
        datetime activated_at
        datetime last_login
        varchar(20) role_id
    }

    T_USER_SESSIONS {
        uuid id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at

        varchar(255) refresh_token_hash
        datetime refresh_expires_at
        varchar(255) ip_address
        text user_agent
        datetime activated_at
        uuid user_id
    }

    T_ROLES {
        uuid id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at
        varchar(20) name
        varchar(20) code
        varchar(100) scope
        text description
    }

    T_ROLES_PERMISSIONS {
        uuid role_id
        uuid permission_id
    }

    T_PERMISSIONS {
        uuid id PK
        datetime created_at
        datetime updated_at
        datetime deleted_at

        varchar(20) resource
        varchar(100) action
        varchar(100) code
        varchar(1000) api_path
        varchar(10) api_method
        text description
    }

    T_USERS ||--o{ T_USER_SESSIONS : user
    T_USERS ||--o{ T_ROLES : role
    T_ROLES ||--o{ T_ROLES_PERMISSIONS : permissions
    T_PERMISSIONS ||--o{ T_ROLES_PERMISSIONS : roles
```

## Design Patterns

### 1. Dependency Injection

Using FastAPI's dependency injection system:

```python
# Dependency Definition
def get_user_service() -> UserService:
    return UserService(user_repository)

# Using Dependencies
@router.post("/users")
async def create_user(
    user_data: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.create_user(user_data)
```

### 2. Warehousing model

Encapsulate data access logic:

```python
class BaseRepository:
    def __init__(self, model: Type[Model]):
        self.model = model

    async def create(self, data: dict) -> Model:
        return await self.model.create(**data)

    async def get_by_id(self, id: int) -> Optional[Model]:
        return await self.model.get_or_none(id=id)
```

### 3. Service layer model

Encapsulate business logic:

```python
class BaseService:
    def __init__(self, repository: BaseRepository):
        self.repository = repository

    async def create(self, data: BaseModel) -> Model:
        # Business logic processing
        validated_data = self.validate_data(data)
        return await self.repository.create(validated_data)
```

## Extension Guide

### Add new functional modules

1. **Create the model** (src/models/):

```python
class Product(EntityBase, TimestampMixin):
    name = fields.CharField(max_length=100)
    price = fields.DecimalField(max_digits=10, decimal_places=2)
```

2. **Create a repository** (src/repositories/):

```python
class ProductRepository(BaseRepository):
    def __init__(self):
        super().__init__(Product)
```

3. **Creating a Service** (src/services/):

```python
class ProductService(BaseService):
    def __init__(self, product_repo: ProductRepository):
        super().__init__(product_repo)
```

4. **Creating an API** (src/api/v1/):

```python
@router.post("/products")
async def create_product(
    product_data: ProductCreate,
    product_service: ProductService = Depends(get_product_service)
):
    return await product_service.create(product_data)
```

### Custom middleware

```python
@app.middleware("http")
async def custom_middleware(request: Request, call_next):
    # Before processing the request
    response = await call_next(request)
    # After processing the response
    return response
```

## Performance optimization

### 1. Database optimization

- Eagerly loading related data using `select_related()`
- Optimizing many-to-many queries with `prefetch_related()`
- Add appropriate database indexes

### 2. Caching strategy

- Use Redis to cache frequently queried data
- Implement query result caching
- Set a reasonable cache expiration time

### 3. Asynchronous processing

- Using asynchronous I/O operations
- Reasonable use of connection pool
- Avoid blocking operations

## Summarize

This architectural design provides:

- ✅ **Clear hierarchy**
- ✅ **High testability**
- ✅ **Good scalability**
- ✅ **Strong type safety**
- ✅ **Complete error handling**

By following these design principles and patterns, you can build stable, efficient, and easy-to-maintain enterprise-level applications.
