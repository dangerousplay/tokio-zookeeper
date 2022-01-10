use sasl::common::{Password, Credentials, parse_frame, Identity, Secret};
use hmac::digest::Digest;
use sasl::client::Mechanism;
use textnonce::TextNonce;
use bytes::{BytesMut, BufMut};


struct MD5Challenge<'a> {
    auth_method: &'a str,
    digest_uri_value: &'a str,
    username: &'a str,
    realm: &'a str,
    password: &'a str,
    nonce: &'a str,
    cnonce: &'a str,
    authzid: &'a str,
    qop: &'a str
}

pub struct MD5 {
    credentials: Credentials,
    max_buffer_size: usize
}

impl Mechanism for MD5 {
    fn name(&self) -> &str {
        "MD5"
    }

    fn from_credentials(credentials: Credentials) -> Result<Self, String> where Self: Sized {
        Ok(Self {
            credentials,
            max_buffer_size: 65536
        })
    }

    fn initial(&mut self) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn response(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        //TODO proper deserialization this inputs
        let frame = parse_frame(challenge).map_err(|_| "can't decode challenge".to_owned())?;

        let mut buffer = BytesMut::new();

        frame.get("algorithm").filter(|a| *a == "md5-sess").ok_or("Invalid algorithm")?;

        let charset = frame.get("charset").filter(|a| *a == "utf-8").ok_or("Invalid Charset")?;
        let nonce = frame.get("nonce").ok_or_else(|| "Not informed Nonce".to_owned())?.replace("\"", "");
        let negotiated_realm = frame.get("realm").ok_or_else(|| "Not informed realm".to_owned())?.replace("\"", "");
        let qop = "auth";

        let cnonce = TextNonce::sized(40).unwrap().into_string();

        let digest_uri = format!("{}/{}", "zookeeper","zk-sasl-md5");

        let username = match self.credentials.identity.clone() {
            Identity::Username(user) => { user },
            Identity::None => { unreachable!() }
        };

        let password = match self.credentials.secret.clone() {
            Secret::Password(password) => { password },
            Secret::None => { unreachable!() }
        };

        let password = match password {
            Password::Plain(password) => password,
            Password::Pbkdf2 { .. } => unreachable!()
        };

        let md5_challenge = MD5Challenge {
            username: username.as_str(),
            realm: negotiated_realm.as_str(),
            digest_uri_value: digest_uri.as_str(),
            password: password.as_str(),
            nonce: nonce.as_str(),
            auth_method: "AUTHENTICATE",
            authzid: username.as_str(),
            qop,
            cnonce: cnonce.as_str()
        };

        let md5_response = generate_response(md5_challenge);

        write_to_buffer(&mut buffer, "charset", charset, false, false);

        write_to_buffer(&mut buffer, "username", username.as_str(), true, false);

        write_to_buffer(&mut buffer, "realm", negotiated_realm.as_str(), true, false);

        write_to_buffer(&mut buffer, "nonce", nonce.as_str(), true, false);

        //nonce count
        write_to_buffer(&mut buffer, "nc", "00000001", false, false);

        write_to_buffer(&mut buffer, "cnonce", cnonce.as_str(), true, false);

        write_to_buffer(&mut buffer, "digest-uri", digest_uri.as_str(), true, false);

        write_to_buffer(&mut buffer, "maxbuf", self.max_buffer_size.to_string().as_str(), false, false);

        write_to_buffer(&mut buffer, "response", md5_response.as_str(), false, false);

        write_to_buffer(&mut buffer, "qop", "auth", false, false);

        write_to_buffer(&mut buffer, "authzid", username.as_str(), true, true);

        Ok(buffer.to_vec())
    }

    fn success(&mut self, data: &[u8]) -> Result<(), String> {
        unimplemented!()
    }
}


fn generate_response(
    challenge: MD5Challenge
) -> String {

    let MD5Challenge {
        auth_method,
        authzid,
        cnonce,
        nonce ,
        password,
        digest_uri_value,
        realm,
        username,
        qop
    } = challenge;

    let mut md5 = md5::Md5::new();

    let mut a2 = BytesMut::new();

    a2.extend(format!("{}:{}", auth_method, digest_uri_value).as_bytes());

    md5.update(a2);

    let hex_a2 = hex::encode(md5.finalize_reset());

    let mut begin_a1 = BytesMut::new();

    begin_a1.extend(format!("{}:{}:{}", username, realm, password).as_bytes());

    md5.update(begin_a1);

    let mut a1 = BytesMut::new();

    a1.put_slice(md5.finalize_reset().as_slice());
    a1.put_slice(b":");

    a1.extend(format!("{}:{}:{}", nonce, cnonce, authzid).as_bytes());

    md5.update(a1);

    let hex_a1 = hex::encode(md5.finalize_reset());

    let mut kd = BytesMut::new();

    kd.put_slice(hex_a1.as_bytes());

    kd.put_slice(&[58]);

    kd.put_slice(nonce.as_bytes());

    kd.put_slice(&[58]);

    kd.put_slice(b"00000001");

    kd.put_slice(&[58]);

    kd.put_slice(cnonce.as_bytes());

    kd.put_slice(&[58]);

    kd.put_slice(qop.as_bytes());

    kd.put_slice(&[58]);

    kd.put_slice(hex_a2.as_bytes());

    md5.update(kd);

    hex::encode(md5.finalize())
}



fn write_to_buffer(buffer: &mut BytesMut, key: &str, value: &str, quoted: bool, last: bool) {
    let value = if quoted { format!("\"{}\"", value) } else { value.to_owned() };
    let value = escape_string(value.as_str());

    buffer.extend(format!("{}={}", key, value).as_bytes());

    if !last {
        buffer.extend(b",")
    }
}

fn escape_string(input: &str) -> String {
    input.chars().map(replace_especial).collect::<String>()
}


#[inline(always)]
fn replace_especial(ch: char) -> char {
    let control = ch >= char::from( 0) && ch <= char::from(31) && ch != '\r' && ch != '\t' && ch != '\n';

    let especial = ch == char::from(127);

    match ch {
        '"' | '\\' if control || especial => 92 as char,
        _ => ch
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use sasl::common::parse_frame;

    #[test]
    fn test_md5_client_response() {
        let challenge = MD5Challenge {
            auth_method: "AUTHENTICATE",
            digest_uri_value: "zookeeper/zk-sasl-md5",
            username: "kafka_user",
            realm: "zk-sasl-md5",
            password: "teste",
            nonce: "JcZ0gj1Zb44V2MMVw7RTq/Ow7LS5fh/46NJPrKVr",
            cnonce: "xFjoIIF4gF8AAAAAc0J6J+Ps4Z2nuZfoLelWoQb/",
            authzid: "kafka_user",
            qop: "auth"
        };

        let actual = generate_response(challenge);

        assert_eq!(actual, "9a619ff0979f4c17e6d6521437e19237");
    }

    #[test]
    fn test_md5_challenge_response() {
        let challenge = generate_challenge();

        let username = "wwt";
        let password = "awd";

        let credentials = Credentials::default()
            .with_username(username)
            .with_password(password);

        let mut mechanism = MD5::from_credentials(credentials).unwrap();

        let challenge_response = mechanism.response(challenge.as_bytes()).expect("No errors");

        let actual = parse_frame(challenge_response.as_slice()).expect("No errors");
        
    }

    fn generate_challenge() -> String {
        let algorithm = "md5-sess";
        let charset = "utf-8";
        let nonce = TextNonce::sized(40).unwrap().into_string();
        let negotiated_realm = "zk-sasl-md5";
        let qop = "auth";

        format!("algorithm={},charset={},nonce=\"{}\",realm=\"{}\"", algorithm, charset, nonce, negotiated_realm)
    }
}