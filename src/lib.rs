use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("jwt token creation error")]
    JWTTokenCreationError,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    nbf: usize, // Optional. Not Before (as UTC timestamp)
    sub: String, // Optional. Subject (whom token refers to)
}

impl Claims {
    pub fn new(aud: String, exp: usize, iat: usize, iss: String, nbf: usize, sub: String) -> Self {
        Claims {
            aud,
            exp,
            iat,
            iss,
            nbf,
            sub,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JWT {}

impl JWT {
    pub fn create(claims: Claims) -> Result<String, Error> {
        let header = Header::new(Algorithm::HS512);
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .map_err(|_| Error::JWTTokenCreationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn create_jwt_token() {
        let claims = Claims::new(
            "".to_string(),
            1231,
            1234,
            "".to_string(),
            123,
            String::from("he"),
        );
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        );
        //println!("token: {:?}", token);
    }
}
