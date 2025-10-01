use actix_web::{Error, HttpMessage, dev::ServiceRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::future::{Ready, ready};

use crate::crypto::{CryptoError, hash_password, verify_password};
use crate::features::data_structs::{Operator, OperatorRole};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // operator ID
    pub username: String,
    pub role: OperatorRole,
    pub exp: i64,    // expiration timestamp
    pub iat: i64,    // issued at timestamp
    pub iss: String, // issuer
}

pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    token_duration: Duration,
}

impl JwtAuth {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_ref()),
            decoding_key: DecodingKey::from_secret(secret.as_ref()),
            issuer: "scythe-c2".to_string(),
            token_duration: Duration::hours(8), // 8 hour token lifetime
        }
    }

    /// Generate JWT token for authenticated operator
    pub fn generate_token(&self, operator: &Operator) -> Result<String, AuthError> {
        let now = Utc::now();
        let claims = Claims {
            sub: operator.id.clone(),
            username: operator.username.clone(),
            role: operator.role.clone(),
            exp: (now + self.token_duration).timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenGenerationFailed)
    }

    /// Validate and decode JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => AuthError::InvalidToken,
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::InvalidToken,
                _ => AuthError::TokenValidationFailed,
            })
    }

    /// Refresh a token if it's still valid
    pub fn refresh_token(&self, token: &str) -> Result<String, AuthError> {
        let claims = self.validate_token(token)?;

        // Check if token is close to expiry (within 1 hour)
        let now = Utc::now().timestamp();
        let time_to_expiry = claims.exp - now;

        if time_to_expiry > 3600 {
            // Token has more than 1 hour left, don't refresh
            return Err(AuthError::TokenNotEligibleForRefresh);
        }

        // Create new token with same claims but updated timestamps
        let new_now = Utc::now();
        let new_claims = Claims {
            sub: claims.sub,
            username: claims.username,
            role: claims.role,
            exp: (new_now + self.token_duration).timestamp(),
            iat: new_now.timestamp(),
            iss: claims.iss,
        };

        encode(&Header::default(), &new_claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenGenerationFailed)
    }
}

pub struct AuthService {
    jwt_auth: JwtAuth,
}

impl AuthService {
    pub fn new(jwt_secret: &str) -> Self {
        Self {
            jwt_auth: JwtAuth::new(jwt_secret),
        }
    }

    /// Authenticate operator with username/password
    pub fn authenticate_operator(
        &self,
        username: &str,
        password: &str,
        operator: &mut Operator,
    ) -> Result<String, AuthError> {
        // Check if operator is locked
        if operator.is_locked() {
            return Err(AuthError::AccountLocked);
        }

        // Verify password
        match verify_password(password, &operator.password_hash) {
            Ok(true) => {
                // Authentication successful
                operator.authenticate();
                self.jwt_auth.generate_token(operator)
            }
            Ok(false) => {
                // Wrong password
                operator.failed_login();
                Err(AuthError::InvalidCredentials)
            }
            Err(_) => Err(AuthError::AuthenticationFailed),
        }
    }

    /// Create new operator account
    pub fn create_operator(
        &self,
        username: String,
        password: &str,
        role: OperatorRole,
    ) -> Result<Operator, AuthError> {
        if password.len() < 8 {
            return Err(AuthError::PasswordTooShort);
        }

        let password_hash =
            hash_password(password).map_err(|_| AuthError::PasswordHashingFailed)?;

        Ok(Operator::new(username, password_hash, role))
    }

    /// Validate bearer token and return claims
    pub fn validate_bearer_token(&self, token: &str) -> Result<Claims, AuthError> {
        self.jwt_auth.validate_token(token)
    }

    /// Refresh token
    pub fn refresh_token(&self, token: &str) -> Result<String, AuthError> {
        self.jwt_auth.refresh_token(token)
    }
}

/// Middleware validator function for Actix Web
pub fn jwt_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Ready<Result<ServiceRequest, (Error, ServiceRequest)>> {
    // Get JWT service from app data
    if let Some(jwt_auth) = req.app_data::<actix_web::web::Data<JwtAuth>>() {
        match jwt_auth.validate_token(credentials.token()) {
            Ok(claims) => {
                // Store claims in request extensions for use in handlers
                req.extensions_mut().insert(claims);
                ready(Ok(req))
            }
            Err(_) => {
                let error = actix_web::error::ErrorUnauthorized("Invalid token");
                ready(Err((error, req)))
            }
        }
    } else {
        let error = actix_web::error::ErrorInternalServerError("JWT service not configured");
        ready(Err((error, req)))
    }
}

/// Authorization helper functions
pub fn require_role(claims: &Claims, required_role: &OperatorRole) -> Result<(), AuthError> {
    match (&claims.role, required_role) {
        // Admin can access everything
        (OperatorRole::Admin, _) => Ok(()),
        // Operator can access Operator and ReadOnly
        (OperatorRole::Operator, OperatorRole::Operator) => Ok(()),
        (OperatorRole::Operator, OperatorRole::ReadOnly) => Ok(()),
        // ReadOnly can only access ReadOnly
        (OperatorRole::ReadOnly, OperatorRole::ReadOnly) => Ok(()),
        // All other combinations are denied
        _ => Err(AuthError::InsufficientPermissions),
    }
}

pub fn require_admin(claims: &Claims) -> Result<(), AuthError> {
    match claims.role {
        OperatorRole::Admin => Ok(()),
        _ => Err(AuthError::InsufficientPermissions),
    }
}

#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidCredentials,
    AccountLocked,
    TokenExpired,
    InvalidToken,
    TokenGenerationFailed,
    TokenValidationFailed,
    TokenNotEligibleForRefresh,
    AuthenticationFailed,
    PasswordTooShort,
    PasswordHashingFailed,
    InsufficientPermissions,
    OperatorNotFound,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid username or password"),
            AuthError::AccountLocked => write!(
                f,
                "Account is temporarily locked due to failed login attempts"
            ),
            AuthError::TokenExpired => write!(f, "Authentication token has expired"),
            AuthError::InvalidToken => write!(f, "Invalid authentication token"),
            AuthError::TokenGenerationFailed => {
                write!(f, "Failed to generate authentication token")
            }
            AuthError::TokenValidationFailed => {
                write!(f, "Failed to validate authentication token")
            }
            AuthError::TokenNotEligibleForRefresh => write!(f, "Token is not eligible for refresh"),
            AuthError::AuthenticationFailed => write!(f, "Authentication failed"),
            AuthError::PasswordTooShort => write!(f, "Password must be at least 8 characters long"),
            AuthError::PasswordHashingFailed => write!(f, "Failed to hash password"),
            AuthError::InsufficientPermissions => {
                write!(f, "Insufficient permissions for this operation")
            }
            AuthError::OperatorNotFound => write!(f, "Operator not found"),
        }
    }
}

impl std::error::Error for AuthError {}

// Convert AuthError to HTTP responses
impl actix_web::ResponseError for AuthError {
    fn error_response(&self) -> actix_web::HttpResponse {
        use actix_web::HttpResponse;
        use serde_json::json;

        let (status, message) = match self {
            AuthError::InvalidCredentials => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "Invalid credentials",
            ),
            AuthError::AccountLocked => (actix_web::http::StatusCode::LOCKED, "Account locked"),
            AuthError::TokenExpired => (actix_web::http::StatusCode::UNAUTHORIZED, "Token expired"),
            AuthError::InvalidToken => (actix_web::http::StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InsufficientPermissions => (
                actix_web::http::StatusCode::FORBIDDEN,
                "Insufficient permissions",
            ),
            AuthError::OperatorNotFound => {
                (actix_web::http::StatusCode::NOT_FOUND, "Operator not found")
            }
            _ => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication error",
            ),
        };

        HttpResponse::build(status).json(json!({
            "error": message,
            "status": "error"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::data_structs::OperatorRole;

    #[test]
    fn test_jwt_token_lifecycle() {
        let jwt_auth = JwtAuth::new("test_secret");
        let operator = Operator::new(
            "test_user".to_string(),
            "$2b$12$test_hash".to_string(),
            OperatorRole::Operator,
        );

        // Generate token
        let token = jwt_auth.generate_token(&operator).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = jwt_auth.validate_token(&token).unwrap();
        assert_eq!(claims.username, "test_user");
        assert!(matches!(claims.role, OperatorRole::Operator));
    }

    #[test]
    fn test_role_authorization() {
        let claims = Claims {
            sub: "test".to_string(),
            username: "test".to_string(),
            role: OperatorRole::Operator,
            exp: 0,
            iat: 0,
            iss: "test".to_string(),
        };

        // Operator should be able to access ReadOnly
        assert!(require_role(&claims, &OperatorRole::ReadOnly).is_ok());

        // Operator should not be able to access Admin
        assert!(require_role(&claims, &OperatorRole::Admin).is_err());
    }
}
