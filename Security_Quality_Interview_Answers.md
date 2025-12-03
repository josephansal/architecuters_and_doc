# Security & Quality Interview Answers - Comprehensive Guide

## 1. Junior-Level Interview Questions (Fundamentals)

### OAuth / JWT

#### What is OAuth 2.0?
OAuth 2.0 is an authorization framework that allows applications to obtain limited access to user accounts on HTTP services.

**Core Concepts:**
- **Resource Owner:** The user who owns the data
- **Client:** The application requesting access
- **Authorization Server:** Validates user identity
- **Resource Server:** Hosts the protected resources
- **Access Token:** Credentials that authorize access

**OAuth Flow Types:**
1. **Authorization Code Flow:** Web applications
2. **Client Credentials Flow:** Machine-to-machine
3. **Implicit Flow:** Single-page applications (legacy)
4. **Resource Owner Password Flow:** Highly trusted applications

```javascript
// Example OAuth 2.0 flow
const authUrl = `https://auth.example.com/oauth/authorize?
  client_id=client123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  scope=read write&
  state=xyz123`;

window.location.href = authUrl;

// Callback handler
async function handleCallback(code) {
  const tokenResponse = await fetch('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'client123',
      client_secret: 'secret456',
      code: code,
      redirect_uri: 'https://app.example.com/callback'
    })
  });
  
  const tokens = await tokenResponse.json();
  return tokens;
}
```

#### What is a JWT?
JSON Web Token (JWT) is a compact, URL-safe means of representing claims between two parties.

**JWT Structure:**
```javascript
// Header
{
  "alg": "RS256",
  "typ": "JWT"
}

// Payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622,
  "aud": "medical-app",
  "iss": "https://auth.example.com",
  "roles": ["doctor", "nurse"]
}

// Signature
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

**JWT vs Session:**
- **JWT:** Stateless, scalable, self-contained
- **Session:** Server-side storage, requires sticky sessions

#### What does a JWT contain (header, payload, signature)?
**Header:**
```javascript
{
  "alg": "RS256",           // Algorithm used for signing
  "typ": "JWT",            // Token type
  "kid": "key-identifier"  // Key ID for key rotation
}
```

**Payload (Claims):**
```javascript
{
  "iss": "https://auth.example.com",        // Issuer
  "sub": "user-123",                        // Subject (user ID)
  "aud": "medical-api",                     // Audience
  "exp": 1701234567,                        // Expiration time
  "iat": 1701230967,                        // Issued at
  "jti": "token-uuid",                      // JWT ID
  "scope": "read:medical write:patients",   // Permissions
  "roles": ["doctor"],                      // User roles
  "tenant_id": "hospital-a"                 // Multi-tenant identifier
}
```

**Signature:**
- **Purpose:** Ensures token hasn't been tampered with
- **Process:** Base64(header) + Base64(payload) signed with private key
- **Verification:** Uses public key to verify signature

#### How does JWT authentication work?
```javascript
// Login process
async function login(username, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  
  const { access_token, refresh_token, expires_in } = await response.json();
  
  // Store tokens
  localStorage.setItem('access_token', access_token);
  localStorage.setItem('refresh_token', refresh_token);
  localStorage.setItem('token_expiry', Date.now() + expires_in * 1000);
  
  return access_token;
}

// Token verification middleware
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.sendStatus(401);
  }
  
  jwt.verify(token, process.env.JWT_PUBLIC_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// API usage with automatic token refresh
async function apiCall(url, options = {}) {
  let token = localStorage.getItem('access_token');
  
  // Check if token needs refresh
  const expiry = localStorage.getItem('token_expiry');
  if (Date.now() > expiry - 300000) { // Refresh 5 minutes before expiry
    token = await refreshToken();
  }
  
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.status === 401 && token === localStorage.getItem('access_token')) {
    // Token was invalid, try refresh
    token = await refreshToken();
    return apiCall(url, options);
  }
  
  return response;
}
```

### RBAC

#### What is Role-Based Access Control (RBAC)?
RBAC restricts system access based on user roles within an organization.

**Key Components:**
- **Roles:** Collections of permissions (doctor, nurse, admin)
- **Users:** Individuals in the system
- **Permissions:** Specific actions (read, write, delete)
- **Role Assignment:** Maps users to roles

```sql
-- RBAC database schema
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
  id INTEGER PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE permissions (
  id INTEGER PRIMARY KEY,
  name VARCHAR(100) UNIQUE NOT NULL,
  resource VARCHAR(50) NOT NULL,
  action VARCHAR(50) NOT NULL,
  CONSTRAINT unique_permission UNIQUE (resource, action)
);

CREATE TABLE role_permissions (
  role_id INTEGER REFERENCES roles(id),
  permission_id INTEGER REFERENCES permissions(id),
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
  user_id INTEGER REFERENCES users(id),
  role_id INTEGER REFERENCES roles(id),
  assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, role_id)
);
```

#### What is the difference between a role and a permission?
**Role:** High-level grouping of permissions
```javascript
const roles = {
  doctor: ['read:patients', 'write:prescriptions', 'read:medical_history'],
  nurse: ['read:patients', 'write:vital_signs'],
  admin: ['read:all_users', 'write:user_roles', 'manage:system']
};
```

**Permission:** Specific action on a resource
```javascript
const permissions = [
  { resource: 'patients', action: 'read' },
  { resource: 'patients', action: 'write' },
  { resource: 'prescriptions', action: 'create' },
  { resource: 'medical_history', action: 'read' }
];
```

#### How do you assign roles to users?
```javascript
// Role assignment service
class RoleManager {
  async assignRole(userId, roleName, tenantId = null) {
    const role = await Role.findOne({ where: { name: roleName } });
    if (!role) {
      throw new Error(`Role '${roleName}' not found`);
    }
    
    // Check for existing assignment
    const existingAssignment = await UserRole.findOne({
      where: { userId, roleId: role.id, tenantId }
    });
    
    if (existingAssignment) {
      throw new Error('User already has this role');
    }
    
    // Create assignment
    const userRole = await UserRole.create({
      userId,
      roleId: role.id,
      tenantId,
      assignedBy: this.getCurrentUserId(),
      assignedAt: new Date()
    });
    
    // Log the assignment
    await this.logRoleChange(userId, roleName, 'ASSIGNED');
    
    return userRole;
  }
  
  async removeRole(userId, roleName, tenantId = null) {
    const role = await Role.findOne({ where: { name: roleName } });
    
    await UserRole.destroy({
      where: {
        userId,
        roleId: role.id,
        tenantId: tenantId || null
      }
    });
    
    await this.logRoleChange(userId, roleName, 'REMOVED');
  }
  
  async getUserRoles(userId, tenantId = null) {
    return await UserRole.findAll({
      where: { userId, tenantId: tenantId || null },
      include: [{ model: Role, include: ['permissions'] }]
    });
  }
}

// Usage
const roleManager = new RoleManager();

// Assign doctor role
await roleManager.assignRole(userId, 'doctor', 'hospital-a');

// Check permissions
function hasPermission(userId, resource, action, tenantId) {
  const roles = await roleManager.getUserRoles(userId, tenantId);
  const permissions = roles.flatMap(r => r.role.permissions);
  
  return permissions.some(p => 
    p.resource === resource && p.action === action
  );
}
```

### Testing

#### What is unit testing?
Unit testing verifies individual components in isolation.

```javascript
// Example: User validation function
function validateUser(user) {
  if (!user.email) return { valid: false, error: 'Email required' };
  if (!user.email.includes('@')) return { valid: false, error: 'Invalid email' };
  if (!user.age || user.age < 18) return { valid: false, error: 'Must be 18+' };
  
  return { valid: true };
}

// Unit tests
describe('validateUser', () => {
  test('validates required email', () => {
    const result = validateUser({ age: 25 });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Email required');
  });
  
  test('validates email format', () => {
    const result = validateUser({ email: 'invalid', age: 25 });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid email');
  });
  
  test('validates age requirement', () => {
    const result = validateUser({ email: 'test@example.com', age: 16 });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Must be 18+');
  });
  
  test('accepts valid user', () => {
    const result = validateUser({ email: 'test@example.com', age: 25 });
    expect(result.valid).toBe(true);
  });
});
```

#### What is integration testing?
Integration testing verifies multiple components working together.

```javascript
// Integration test: User registration flow
describe('User Registration Integration', () => {
  beforeAll(async () => {
    await setupTestDatabase();
  });
  
  afterAll(async () => {
    await cleanupTestDatabase();
  });
  
  test('registers user and sends welcome email', async () => {
    // 1. Create user account
    const user = await UserService.create({
      email: 'test@example.com',
      password: 'securepassword123',
      name: 'Test User'
    });
    
    expect(user.id).toBeDefined();
    expect(user.email).toBe('test@example.com');
    
    // 2. Verify database record
    const dbUser = await User.findById(user.id);
    expect(dbUser.email).toBe(user.email);
    expect(dbUser.passwordHash).toBeDefined();
    
    // 3. Verify welcome email was sent
    expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(
      user.email,
      user.name
    );
    
    // 4. Verify user can authenticate
    const loginResult = await AuthService.login(
      'test@example.com',
      'securepassword123'
    );
    expect(loginResult.token).toBeDefined();
  });
});
```

#### What is mocking?
Mocking replaces real dependencies with test doubles.

```javascript
// Service that depends on external API
class MedicalDeviceService {
  constructor(deviceApi, notificationService) {
    this.deviceApi = deviceApi;
    this.notificationService = notificationService;
  }
  
  async registerDevice(deviceData) {
    try {
      const device = await this.deviceApi.register(deviceData);
      
      // Send notification on success
      await this.notificationService.sendNotification({
        type: 'device_registered',
        deviceId: device.id,
        message: 'New medical device registered successfully'
      });
      
      return device;
    } catch (error) {
      // Log error and rethrow
      console.error('Device registration failed:', error);
      throw error;
    }
  }
}

// Test with mocks
describe('MedicalDeviceService', () => {
  let service;
  let mockDeviceApi;
  let mockNotificationService;
  
  beforeEach(() => {
    mockDeviceApi = {
      register: jest.fn(),
      getDeviceStatus: jest.fn()
    };
    
    mockNotificationService = {
      sendNotification: jest.fn()
    };
    
    service = new MedicalDeviceService(mockDeviceApi, mockNotificationService);
  });
  
  test('registers device and sends notification', async () => {
    // Setup mock response
    mockDeviceApi.register.mockResolvedValue({
      id: 'device-123',
      type: 'heart_monitor',
      status: 'active'
    });
    
    const deviceData = { type: 'heart_monitor', location: 'ICU-1' };
    const result = await service.registerDevice(deviceData);
    
    // Verify device registration was called
    expect(mockDeviceApi.register).toHaveBeenCalledWith(deviceData);
    expect(result.id).toBe('device-123');
    
    // Verify notification was sent
    expect(mockNotificationService.sendNotification).toHaveBeenCalledWith({
      type: 'device_registered',
      deviceId: 'device-123',
      message: 'New medical device registered successfully'
    });
  });
  
  test('handles registration failure', async () => {
    const error = new Error('Registration failed');
    mockDeviceApi.register.mockRejectedValue(error);
    
    await expect(service.registerDevice({})).rejects.toThrow('Registration failed');
    
    // Verify notification was NOT sent on failure
    expect(mockNotificationService.sendNotification).not.toHaveBeenCalled();
  });
});
```

### Agile Practices

#### What is Agile?
Agile is an iterative approach to software development emphasizing flexibility, collaboration, and customer feedback.

**Agile Manifesto Values:**
1. **Individuals and interactions** over processes and tools
2. **Working software** over comprehensive documentation
3. **Customer collaboration** over contract negotiation
4. **Responding to change** over following a plan

**Agile Principles:**
- Customer satisfaction through early delivery
- Welcome changing requirements
- Deliver working software frequently
- Business people and developers work together
- Build projects around motivated individuals
- Face-to-face conversation for efficiency
- Working software as primary measure of progress
- Sustainable development pace
- Technical excellence and good design
- Simplicity through maximizing work not done
- Self-organizing teams
- Regular reflection and adjustment

#### What is Scrum?
Scrum is a framework for developing, delivering, and sustaining complex products.

**Scrum Framework:**
- **Sprint:** Time-boxed iteration (usually 1-4 weeks)
- **Product Backlog:** Ordered list of features
- **Sprint Backlog:** Selected items + plan for Sprint
- **Increment:** Potentially shippable product

**Scrum Roles:**
- **Product Owner:** Defines product vision and priorities
- **Scrum Master:** Facilitates Scrum process
- **Development Team:** Cross-functional, self-organizing

**Scrum Events:**
- **Sprint Planning:** Plan work for Sprint
- **Daily Scrum:** Daily sync meeting (15 minutes)
- **Sprint Review:** Demonstrate work to stakeholders
- **Sprint Retrospective:** Improve process

#### What are the main Scrum ceremonies?
```javascript
// Sprint Planning example structure
const sprintPlanning = {
  duration: '8 hours for 4-week sprint',
  participants: ['Product Owner', 'Scrum Master', 'Development Team'],
  objectives: [
    'Review Product Backlog priorities',
    'Select Sprint Backlog items',
    'Define Sprint Goal',
    'Estimate capacity and commitments',
    'Create task breakdown'
  ],
  inputs: ['Product Backlog', 'Velocity history', 'Team capacity'],
  outputs: ['Sprint Goal', 'Sprint Backlog', 'Task breakdown']
};

// Daily Scrum structure
const dailyScrum = {
  duration: '15 minutes',
  participants: ['Scrum Team'],
  format: [
    'What did I do yesterday?',
    'What will I do today?',
    'What impediments do I have?'
  ],
  purpose: 'Inspect progress toward Sprint Goal and adapt plan'
};

// Sprint Review structure
const sprintReview = {
  duration: '4 hours for 4-week sprint',
  participants: ['Scrum Team', 'Stakeholders', 'Customers'],
  activities: [
    'Demonstrate completed work',
    'Collect feedback',
    'Update Product Backlog',
    'Discuss what went well and challenges'
  ]
};

// Sprint Retrospective structure
const sprintRetrospective = {
  duration: '3 hours for 4-week sprint',
  participants: ['Scrum Team only'],
  format: [
    'Set the stage (5 min)',
    'Gather data (30 min)',
    'Generate insights (30 min)',
    'Decide what to do (30 min)',
    'Close (15 min)'
  ],
  outputs: ['Improvement items', 'Action commitments']
};
```

## 2. Senior-Level Interview Questions (Deep Implementation)

### OAuth / JWT

#### Describe the OAuth 2.0 Authorization Code Flow.
```javascript
// Complete Authorization Code Flow implementation
class OAuthService {
  // Step 1: Generate authorization URL
  generateAuthUrl(clientId, redirectUri, scopes, state) {
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      state: state
    });
    
    return `https://auth.example.com/oauth/authorize?${params}`;
  }
  
  // Step 2: Exchange code for tokens
  async exchangeCodeForTokens(code, clientId, clientSecret, redirectUri) {
    const tokenResponse = await fetch('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri
      })
    });
    
    if (!tokenResponse.ok) {
      throw new Error('Token exchange failed');
    }
    
    const tokens = await tokenResponse.json();
    
    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      scope: tokens.scope
    };
  }
  
  // Step 3: Refresh access token
  async refreshAccessToken(refreshToken, clientId, clientSecret) {
    const response = await fetch('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken
      })
    });
    
    const tokens = await response.json();
    
    return {
      access_token: tokens.access_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      scope: tokens.scope
      // Note: Some providers issue new refresh tokens, others reuse existing
    };
  }
}

// Client-side implementation
class OAuthClient {
  constructor(config) {
    this.config = config;
    this.stateKey = 'oauth_state';
    this.pkceVerifierKey = 'pkce_verifier';
  }
  
  // Generate PKCE challenge for public clients
  generateCodeChallenge() {
    const verifier = this.generateRandomString(128);
    const challenge = base64url(sha256(verifier));
    
    sessionStorage.setItem(this.pkceVerifierKey, verifier);
    return { verifier, challenge };
  }
  
  async initiateLogin() {
    const state = this.generateRandomString(32);
    const { verifier, challenge } = this.generateCodeChallenge();
    
    sessionStorage.setItem(this.stateKey, state);
    
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      state: state,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    
    window.location.href = `https://auth.example.com/oauth/authorize?${params}`;
  }
  
  async handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');
    
    if (error) {
      throw new Error(`OAuth error: ${error}`);
    }
    
    if (!code || !state) {
      throw new Error('Missing authorization code or state');
    }
    
    // Verify state parameter
    const storedState = sessionStorage.getItem(this.stateKey);
    if (state !== storedState) {
      throw new Error('State parameter mismatch');
    }
    
    sessionStorage.removeItem(this.stateKey);
    
    // Exchange code for tokens
    const verifier = sessionStorage.getItem(this.pkceVerifierKey);
    sessionStorage.removeItem(this.pkceVerifierKey);
    
    return await this.oauthService.exchangeCodeForTokens(
      code,
      this.config.clientId,
      this.config.clientSecret,
      this.config.redirectUri
    );
  }
  
  generateRandomString(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => 
      ('0' + byte.toString(16)).slice(-2)
    ).join('');
  }
}
```

#### What is PKCE and why is it important?
PKCE (Proof Key for Code Exchange) adds security to OAuth flows for public clients.

```javascript
// PKCE implementation
class PKCEGenerator {
  static generateVerifier(length = 128) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let verifier = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    
    randomValues.forEach(value => {
      verifier += chars[value % chars.length];
    });
    
    return verifier;
  }
  
  static async generateChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    
    return this.base64urlEncode(new Uint8Array(digest));
  }
  
  static base64urlEncode(array) {
    let str = '';
    array.forEach(byte => {
      str += String.fromCharCode(byte);
    });
    
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}

// Usage in login flow
async function loginWithPKCE() {
  // 1. Generate PKCE pair
  const verifier = PKCEGenerator.generateVerifier();
  const challenge = await PKCEGenerator.generateChallenge(verifier);
  
  // 2. Store verifier for later
  sessionStorage.setItem('pkce_verifier', verifier);
  
  // 3. Redirect to authorization endpoint
  const params = new URLSearchParams({
    client_id: 'medical-app-client',
    redirect_uri: 'https://app.example.com/callback',
    response_type: 'code',
    scope: 'read:medical write:prescriptions',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: crypto.randomUUID()
  });
  
  window.location.href = `https://auth.example.com/oauth/authorize?${params}`;
}

// Handle callback with PKCE verification
async function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const verifier = sessionStorage.getItem('pkce_verifier');
  
  if (!verifier) {
    throw new Error('PKCE verifier not found');
  }
  
  // Exchange code for tokens with PKCE
  const tokens = await fetch('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'medical-app-client',
      code: code,
      redirect_uri: 'https://app.example.com/callback',
      code_verifier: verifier
    })
  }).then(res => res.json());
  
  // Store tokens securely
  localStorage.setItem('access_token', tokens.access_token);
  sessionStorage.removeItem('pkce_verifier');
  
  return tokens;
}
```

#### How do you securely store JWTs in a browser?
```javascript
// Secure token storage strategies
class TokenManager {
  constructor() {
    this.storage = 'httpOnly'; // 'httpOnly', 'memory', 'secureLocalStorage'
  }
  
  // Strategy 1: HTTP-only cookies (most secure)
  async storeTokensInCookies(accessToken, refreshToken) {
    const secureOptions = {
      httpOnly: true,
      secure: true, // HTTPS only
      sameSite: 'strict',
      maxAge: 3600 // 1 hour
    };
    
    // Set access token cookie
    document.cookie = `access_token=${accessToken}; ${this.cookieOptionsToString(secureOptions)}`;
    
    // Set refresh token cookie with longer expiry
    const refreshOptions = { ...secureOptions, maxAge: 2592000 }; // 30 days
    document.cookie = `refresh_token=${refreshToken}; ${this.cookieOptionsToString(refreshOptions)}`;
  }
  
  // Strategy 2: In-memory storage (recommended for SPAs)
  storeTokensInMemory(accessToken, refreshToken) {
    this.tokens = { accessToken, refreshToken };
  }
  
  // Strategy 3: Secure localStorage (less secure but necessary for some cases)
  storeTokensSecurely(accessToken, refreshToken) {
    // Encrypt tokens before storing
    const encryptedTokens = this.encryptTokens({ accessToken, refreshToken });
    localStorage.setItem('encrypted_tokens', encryptedTokens);
  }
  
  // Auto-refresh tokens before expiry
  setupTokenRefresh(refreshToken) {
    setInterval(async () => {
      try {
        const newTokens = await this.refreshAccessToken(refreshToken);
        this.storeTokens(newTokens.access_token, newTokens.refresh_token);
      } catch (error) {
        console.error('Token refresh failed:', error);
        this.clearTokens();
        // Redirect to login
        window.location.href = '/login';
      }
    }, 15 * 60 * 1000); // Check every 15 minutes
  }
  
  // CSRF protection for token-based APIs
  getCSRFToken() {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (!csrfToken) {
      throw new Error('CSRF token not found');
    }
    return csrfToken;
  }
  
  // Secure API calls with CSRF protection
  async secureApiCall(url, options = {}) {
    const csrfToken = this.getCSRFToken();
    
    const secureOptions = {
      ...options,
      headers: {
        ...options.headers,
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
      },
      credentials: 'include' // Send cookies
    };
    
    return await fetch(url, secureOptions);
  }
}

// Usage example
const tokenManager = new TokenManager();

// During login
async function login(credentials) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials)
  });
  
  if (response.ok) {
    const { access_token, refresh_token } = await response.json();
    tokenManager.storeTokensInMemory(access_token, refresh_token);
    tokenManager.setupTokenRefresh(refresh_token);
  }
  
  return response;
}

// Automatic token refresh on 401 responses
function createSecureApiClient() {
  const originalFetch = window.fetch;
  
  window.fetch = async function(url, options = {}) {
    try {
      const response = await originalFetch(url, options);
      
      if (response.status === 401) {
        // Try to refresh token
        const refreshed = await tokenManager.refreshAccessToken();
        if (refreshed) {
          // Retry original request with new token
          const retryOptions = {
            ...options,
            headers: {
              ...options.headers,
              'Authorization': `Bearer ${refreshed.access_token}`
            }
          };
          return await originalFetch(url, retryOptions);
        }
      }
      
      return response;
    } catch (error) {
      console.error('API call failed:', error);
      throw error;
    }
  };
}
```

### RBAC

#### How do you design a role-permission model?
```javascript
// Hierarchical RBAC implementation
class RBACSystem {
  constructor() {
    this.roles = new Map();
    this.permissions = new Map();
    this.userRoles = new Map();
    this.roleHierarchy = new Map();
  }
  
  // Define permissions with resource-level granularity
  definePermissions() {
    const permissions = [
      // Patient data permissions
      { name: 'read:patients', resource: 'patients', action: 'read' },
      { name: 'write:patients', resource: 'patients', action: 'write' },
      { name: 'delete:patients', resource: 'patients', action: 'delete' },
      { name: 'emergency:access', resource: 'patients', action: 'emergency_access' },
      
      // Medical records permissions
      { name: 'read:medical_records', resource: 'medical_records', action: 'read' },
      { name: 'write:medical_records', resource: 'medical_records', action: 'write' },
      
      // System administration permissions
      { name: 'manage:users', resource: 'users', action: 'manage' },
      { name: 'manage:roles', resource: 'roles', action: 'manage' },
      { name: 'audit:system', resource: 'system', action: 'audit' }
    ];
    
    permissions.forEach(perm => this.permissions.set(perm.name, perm));
  }
  
  // Define roles with inherited permissions
  defineRoles() {
    const roleDefs = [
      {
        name: 'nurse',
        permissions: ['read:patients', 'write:patients', 'read:medical_records'],
        inherits: []
      },
      {
        name: 'doctor',
        permissions: ['read:patients', 'write:patients', 'delete:patients', 'read:medical_records', 'write:medical_records'],
        inherits: ['nurse']
      },
      {
        name: 'emergency_doctor',
        permissions: ['emergency:access'],
        inherits: ['doctor']
      },
      {
        name: 'admin',
        permissions: ['manage:users', 'manage:roles', 'audit:system'],
        inherits: ['doctor']
      }
    ];
    
    roleDefs.forEach(roleDef => {
      this.roles.set(roleDef.name, roleDef);
    });
    
    // Build role hierarchy graph
    this.buildRoleHierarchy();
  }
  
  // Build role inheritance hierarchy
  buildRoleHierarchy() {
    this.roles.forEach((roleDef, roleName) => {
      const inheritedPermissions = new Set();
      
      // Collect permissions from parent roles
      const collectInheritedPermissions = (roleName) => {
        const role = this.roles.get(roleName);
        role.permissions.forEach(perm => inheritedPermissions.add(perm));
        
        role.inherits.forEach(parentRole => {
          collectInheritedPermissions(parentRole);
        });
      };
      
      collectInheritedPermissions(roleName);
      this.roleHierarchy.set(roleName, Array.from(inheritedPermissions));
    });
  }
  
  // Check if user has specific permission
  hasPermission(userId, permissionName, context = {}) {
    const userRolePermissions = this.getUserEffectivePermissions(userId);
    const permission = this.permissions.get(permissionName);
    
    if (!permission) return false;
    
    // Check if user has the base permission
    if (!userRolePermissions.includes(permissionName)) {
      return false;
    }
    
    // Additional context-based checks
    if (permissionName === 'emergency:access') {
      // Emergency access only during emergency situations
      return context.emergencyActive === true;
    }
    
    if (permission.resource === 'patients') {
      // Check patient access rights
      return this.canAccessPatient(userId, context.patientId, userRolePermissions);
    }
    
    return true;
  }
  
  // Check patient access based on role and context
  canAccessPatient(userId, patientId, userPermissions) {
    const user = this.getUser(userId);
    const patient = this.getPatient(patientId);
    
    // Admin and emergency roles can access all patients
    if (userPermissions.includes('admin:*') || 
        userPermissions.includes('emergency:access')) {
      return true;
    }
    
    // Check if user is assigned to this patient's care team
    const careTeam = patient.careTeam || [];
    return careTeam.some(member => member.userId === userId);
  }
  
  // Get all effective permissions for a user
  getUserEffectivePermissions(userId) {
    const userRoles = this.getUserRoles(userId);
    const allPermissions = new Set();
    
    userRoles.forEach(roleName => {
      const rolePermissions = this.roleHierarchy.get(roleName) || [];
      rolePermissions.forEach(perm => allPermissions.add(perm));
    });
    
    return Array.from(allPermissions);
  }
  
  // Permission evaluation middleware
  createPermissionMiddleware(requiredPermission, contextBuilder = null) {
    return (req, res, next) => {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      
      let context = {};
      if (contextBuilder) {
        context = contextBuilder(req);
      }
      
      if (!this.hasPermission(userId, requiredPermission, context)) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          required: requiredPermission,
          context 
        });
      }
      
      next();
    };
  }
}

// Express.js middleware usage
const rbac = new RBACSystem();
rbac.definePermissions();
rbac.defineRoles();

// Route protection
app.get('/api/patients/:patientId', 
  authenticateUser,
  rbac.createPermissionMiddleware('read:patients', (req) => ({
    patientId: req.params.patientId
  })),
  getPatient
);

app.post('/api/emergency/access/:patientId',
  authenticateUser,
  rbac.createPermissionMiddleware('emergency:access', (req) => ({
    patientId: req.params.patientId,
    emergencyActive: true // Check emergency status
  })),
  emergencyAccess
);
```

#### How do you enforce RBAC in an API?
```javascript
// API-level RBAC enforcement
class APIRBAC {
  constructor(rbacSystem) {
    this.rbac = rbacSystem;
    this.auditLogger = new AuditLogger();
  }
  
  // Global RBAC middleware
  enforceRBAC(requiredPermission, resourceResolver = null) {
    return async (req, res, next) => {
      try {
        const userId = req.user?.id;
        if (!userId) {
          return res.status(401).json({ error: 'Authentication required' });
        }
        
        // Build context for permission evaluation
        let context = {
          userId,
          tenantId: req.user.tenantId,
          requestMethod: req.method,
          requestPath: req.path
        };
        
        // Extract resource identifier from request
        if (resourceResolver) {
          const resourceInfo = resourceResolver(req);
          context = { ...context, ...resourceInfo };
        }
        
        // Check permission
        const hasPermission = await this.rbac.hasPermission(userId, requiredPermission, context);
        
        if (!hasPermission) {
          // Log access denial
          await this.auditLogger.logAccessDenied({
            userId,
            permission: requiredPermission,
            context,
            ip: req.ip,
            userAgent: req.get('User-Agent')
          });
          
          return res.status(403).json({
            error: 'Access denied',
            required: requiredPermission,
            context
          });
        }
        
        // Log successful access
        await this.auditLogger.logAccessGranted({
          userId,
          permission: requiredPermission,
          context,
          ip: req.ip
        });
        
        req.context = context;
        next();
        
      } catch (error) {
        console.error('RBAC enforcement error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  }
  
  // Resource-specific resolvers
  patientResolver(req) {
    return {
      resourceType: 'patient',
      patientId: req.params.patientId || req.body.patientId,
      department: req.user.department
    };
  }
  
  medicalRecordResolver(req) {
    return {
      resourceType: 'medical_record',
      recordId: req.params.recordId || req.body.recordId,
      patientId: req.body.patientId
    };
  }
  
  // Tenant isolation middleware
  enforceTenantIsolation() {
    return (req, res, next) => {
      const userTenantId = req.user?.tenantId;
      const requestedTenantId = req.params.tenantId || req.query.tenantId;
      
      if (requestedTenantId && requestedTenantId !== userTenantId) {
        return res.status(403).json({
          error: 'Cross-tenant access denied',
          userTenantId,
          requestedTenantId
        });
      }
      
      // Add tenant filter to query
      if (req.query) {
        req.query.tenantId = userTenantId;
      }
      
      if (req.body && !req.body.tenantId) {
        req.body.tenantId = userTenantId;
      }
      
      next();
    };
  }
}

// Comprehensive API protection example
const apiRBAC = new APIRBAC(rbac);

app.use('/api/patients', 
  authenticateUser, // Verify JWT
  apiRBAC.enforceTenantIsolation()
);

// Patient routes
app.get('/api/patients/:patientId',
  apiRBAC.enforceRBAC('read:patients', apiRBAC.patientResolver),
  getPatient
);

app.put('/api/patients/:patientId',
  apiRBAC.enforceRBAC('write:patients', apiRBAC.patientResolver),
  updatePatient
);

app.delete('/api/patients/:patientId',
  apiRBAC.enforceRBAC('delete:patients', apiRBAC.patientResolver),
  deletePatient
);

// Emergency access (special permission)
app.post('/api/emergency/patients/:patientId/access',
  apiRBAC.enforceRBAC('emergency:access', (req) => ({
    ...apiRBAC.patientResolver(req),
    emergencyActive: req.body.emergencyActive === true
  })),
  emergencyPatientAccess
);

// Admin routes
app.post('/api/users',
  apiRBAC.enforceRBAC('manage:users'),
  createUser
);

app.get('/api/users/:userId/permissions',
  apiRBAC.enforceRBAC('audit:system'),
  getUserPermissions
);

// Audit trail middleware
app.post('/api/audit/log',
  apiRBAC.enforceRBAC('audit:system'),
  logAuditEvent
);
```

### Testing

#### How do you mock external API calls?
```javascript
// Comprehensive API mocking strategies

// 1. HTTP Client Mocking
describe('MedicalDeviceService', () => {
  let medicalService;
  let mockHttpClient;
  let mockLogger;
  
  beforeEach(() => {
    mockHttpClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    };
    
    mockLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn()
    };
    
    medicalService = new MedicalDeviceService(mockHttpClient, mockLogger);
  });
  
  describe('getDeviceStatus', () => {
    test('returns device status for valid device ID', async () => {
      // Setup mock response
      const mockResponse = {
        deviceId: 'device-123',
        status: 'active',
        batteryLevel: 85,
        lastSeen: '2023-12-03T10:00:00Z'
      };
      
      mockHttpClient.get.mockResolvedValue({
        status: 200,
        data: mockResponse
      });
      
      const result = await medicalService.getDeviceStatus('device-123');
      
      expect(result).toEqual(mockResponse);
      expect(mockHttpClient.get).toHaveBeenCalledWith(
        '/api/devices/device-123/status'
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        'Retrieved device status',
        { deviceId: 'device-123' }
      );
    });
    
    test('handles device not found error', async () => {
      mockHttpClient.get.mockRejectedValue({
        response: { status: 404, data: { message: 'Device not found' } }
      });
      
      await expect(medicalService.getDeviceStatus('invalid-device'))
        .rejects.toThrow('Device not found');
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'Failed to retrieve device status',
        expect.objectContaining({
          deviceId: 'invalid-device',
          error: expect.any(Error)
        })
      );
    });
    
    test('handles network timeout', async () => {
      mockHttpClient.get.mockRejectedValue({
        code: 'ECONNABORTED',
        message: 'Request timeout'
      });
      
      await expect(medicalService.getDeviceStatus('device-123'))
        .rejects.toThrow('Request timeout');
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'Network timeout while retrieving device status',
        expect.any(Object)
      );
    });
  });
});

// 2. Service Layer Mocking with TestContainers
describe('Integration Tests with TestContainers', () => {
  let postgresContainer;
  let redisContainer;
  
  beforeAll(async () => {
    // Start PostgreSQL container
    postgresContainer = await new PostgreSqlContainer()
      .withDatabase('medical_db')
      .withUsername('test')
      .withPassword('test')
      .start();
    
    // Start Redis container
    redisContainer = await new RedisContainer().start();
  });
  
  afterAll(async () => {
    await postgresContainer.stop();
    await redisContainer.stop();
  });
  
  test('processes medical device data with real database', async () => {
    // Setup test database
    await setupTestDatabase(postgresContainer);
    
    const deviceService = new DeviceService({
      db: postgresContainer.getConnection(),
      redis: redisContainer.getConnection()
    });
    
    const deviceData = {
      deviceId: 'test-device-123',
      patientId: 'patient-456',
      vitalSigns: {
        heartRate: 75,
        bloodPressure: 120,
        oxygenSat: 98
      },
      timestamp: new Date().toISOString()
    };
    
    const result = await deviceService.processVitalSigns(deviceData);
    
    expect(result.status).toBe('processed');
    expect(result.alertLevel).toBe('normal');
    
    // Verify data was stored
    const storedData = await deviceService.getDeviceData('test-device-123');
    expect(storedData.vitalSigns).toEqual(deviceData.vitalSigns);
  });
});

// 3. MSW (Mock Service Worker) for API mocking
import { setupServer } from 'msw/node';
import { rest } from 'msw';

const server = setupServer(
  rest.get('/api/patients/:patientId', (req, res, ctx) => {
    return res(
      ctx.json({
        id: req.params.patientId,
        name: 'John Doe',
        age: 45,
        medicalHistory: ['diabetes', 'hypertension']
      })
    );
  }),
  
  rest.post('/api/patients', (req, res, ctx) => {
    const patient = JSON.parse(req.body);
    return res(
      ctx.status(201),
      ctx.json({
        id: 'patient-123',
        ...patient,
        createdAt: new Date().toISOString()
      })
    );
  }),
  
  rest.put('/api/patients/:patientId', (req, res, ctx) => {
    return res(
      ctx.json({
        id: req.params.patientId,
        ...JSON.parse(req.body),
        updatedAt: new Date().toISOString()
      })
    );
  })
);

// Start server before tests
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// 4. WireMock for complex API mocking
describe('WireMock API Mocking', () => {
  let wireMockServer;
  
  beforeAll(async () => {
    wireMockServer = new WireMockServer({ port: 8089 });
    await wireMockServer.start();
  });
  
  afterAll(async () => {
    await wireMockServer.stop();
  });
  
  test('handles complex authentication flow', async () => {
    // Setup authentication endpoint
    await wireMockServer.stubFor(
      post(urlEqualTo('/oauth/token'))
        .withRequestBody(
          matchingJsonPath('$.grant_type', equalTo('authorization_code'))
        )
        .willReturn(
          aResponse()
            .withStatus(200)
            .withHeader('Content-Type', 'application/json')
            .withBody(JSON.stringify({
              access_token: 'mock_access_token_123',
              refresh_token: 'mock_refresh_token_456',
              expires_in: 3600,
              token_type: 'Bearer'
            }))
        )
    );
    
    // Setup user info endpoint
    await wireMockServer.stubFor(
      get(urlEqualTo('/api/user/info'))
        .withHeader('Authorization', matching('Bearer .*'))
        .willReturn(
          aResponse()
            .withStatus(200)
            .withHeader('Content-Type', 'application/json')
            .withBody(JSON.stringify({
              id: 'user-123',
              name: 'Dr. Jane Smith',
              roles: ['doctor'],
              permissions: ['read:patients', 'write:prescriptions']
            }))
        )
    );
    
    // Test the authentication flow
    const authService = new AuthService({
      baseUrl: 'http://localhost:8089',
      clientId: 'test-client',
      clientSecret: 'test-secret'
    });
    
    const tokens = await authService.exchangeCodeForTokens('auth_code_123');
    expect(tokens.access_token).toBe('mock_access_token_123');
    
    const userInfo = await authService.getUserInfo(tokens.access_token);
    expect(userInfo.roles).toContain('doctor');
  });
});
```

This comprehensive security and quality interview answer document demonstrates deep understanding of authentication systems, authorization frameworks, testing strategies, and agile methodologies essential for senior-level technical positions.