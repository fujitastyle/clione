use std::fs;
use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::service::{make_service_fn, service_fn};
use hyper::{header, Body, Method, Request, Response, Server, StatusCode, Client};
use hyper_tls::HttpsConnector;
use serde_json::json;

use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;

use chrono::Utc;

const hostname: &str = "relay.misoni.club";


async fn get_hostmeta() -> Result<Response<Body>, Infallible> {
    let data = vec!{"XML","xml"};
    let res = match serde_json::to_string(&data) {
        Ok(json) => Response::builder()
            .header(header::CONTENT_TYPE, "application/xrd+xml")
            .body(Body::from(json))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("INTERNAL SERVER ERROR"))
            .unwrap()
    };
    println!("GET:/.well-known/host-meta");
    Ok(res)
}

async fn get_webfinger() -> Result<Response<Body>, Infallible> {
    let data =  json!({
        "subject": format!("acct:relay@{}", hostname), 
        "aliases": [
            format!("https://{}/actor", hostname)
        ],
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": format!("https://{}/actor", hostname)
            },
            {
                "rel": "self",
                "type": "application/json+ld",
                "href": format!("https://{}/actor", hostname)
            }
        ]
    });
    let res = match serde_json::to_string(&data) {
        Ok(json) => Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("INTERNAL SERVER ERROR"))
            .unwrap()
    };
    println!("GET:/.well-known/webfinger");
    Ok(res)
}

async fn get_actor() -> Result<Response<Body>, Infallible> {
    //いちいち開くな
    let pem = fs::read_to_string("./public.pem").unwrap();

    let data = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],
        "id": format!("https://{}/actor", hostname),
        "type": "Application",
        "preferredUsername": "relay",
        "name": "clione",
        "summary": "activitypub relay",
        "url": format!("https://{}/actor", hostname),
        "inbox": format!("https://{}/inbox", hostname),
        "endpoints": {
            "sharedInbox": format!("https://{}/inbox", hostname)
        },
        "publicKey": {
            "id": format!("https://{}/actor#main-key", hostname),
            "owner": format!("https://{}/actor", hostname),
            "publicKeyPem": pem
        }
    });
    let res = match serde_json::to_string(&data) {
        Ok(json) => Response::builder()
            .header(header::CONTENT_TYPE, "application/activity+json")
            .body(Body::from(json))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("INTERNAL SERVER ERROR"))
            .unwrap()
    };
    println!("GET:/actor");
    Ok(res)
}


async fn post_inbox(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req).await.unwrap();
    let body = String::from_utf8(body_bytes.to_vec()).unwrap();
    let activity: serde_json::Value = serde_json::from_str(&body).unwrap();
    
    println!("->{}", activity["type"].as_str().unwrap());
    println!("{}",serde_json::to_string(&activity).unwrap());

if(activity["type"].as_str().unwrap() == "Follow" || activity["type"].as_str().unwrap() == "Undo"){
    let accept = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Accept",
        "actor": format!("https://{}/actor", hostname),
        "object": activity
    });
    println!("Accept->");
    println!("{}", serde_json::to_string(&accept).unwrap());

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let actor_url = activity["actor"].as_str().unwrap();
    println!("get {}=>",actor_url);

    let actor_req = Request::builder()
        .method(Method::GET)
        .uri(actor_url)
        .header(header::ACCEPT, "application/activity+json")
        .body(Body::from(""))
        .unwrap();
    let actor_res = client.request(actor_req).await.unwrap();
    println!("status:{}",actor_res.status());
    let actor_body_bytes = hyper::body::to_bytes(actor_res).await.unwrap();
    let actor_body = String::from_utf8(actor_body_bytes.to_vec()).unwrap();
    let actor: serde_json::Value = serde_json::from_str(&actor_body).unwrap();

    let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let sign = http_signature(&date).await.unwrap();
    let signature = format!("keyId=\"https://{}/actor#main-key\",algorithm=\"rsa-sha256\",signature=\"{}\"",hostname,sign);
  
    let actor_inbox_url = actor["inbox"].as_str().unwrap();
    println!("post {}=>",actor_inbox_url);

    let actor_inbox_req = Request::builder()
        .method(Method::POST)
        .uri(actor_inbox_url)
        .header("date", date)
        .header(header::CONTENT_TYPE, "application/activity+json")
        .header("signature", signature)
        .body(Body::from(serde_json::to_string(&accept).unwrap()))
        .unwrap();

    let actor_inbox_res = client.request(actor_inbox_req).await.unwrap();
    println!("status:{}", actor_inbox_res.status());
}
    let res = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Body::from("inbox"))
        .unwrap();
    println!("POST:/inbox");
    Ok(res)

}

async fn http_signature(date: &String) -> Result<String, Infallible> {
    let pem = fs::read_to_string("./private.pem").unwrap();
    let rsa = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();
    let keypair = PKey::from_rsa(rsa).unwrap();
    let signed_string = format!("date: {}",date);
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(signed_string.as_bytes()).unwrap();
    let signature_bytes = signer.sign_to_vec().unwrap();
    let signature = base64::encode(signature_bytes);
    Ok(signature)
}

async fn router(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/.well-known/host-meta") => get_hostmeta().await,
        (&Method::GET, "/.well-known/webfinger") => get_webfinger().await,
        (&Method::GET, "/actor") => get_actor().await,
        (&Method::POST, "/inbox") => post_inbox(req).await,
        (&Method::POST, "/.well-known/host-meta") |
        (&Method::POST, "/.well-known/webfinger") | 
        (&Method::POST, "/actor") |
        (&Method::GET, "/inbox") => {
            Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("BAD REQUEST"))
            .unwrap())
        },
        (&Method::GET, "/") => {
            Ok(Response::builder()
            .body(Body::from("index"))
            .unwrap())
        },
        _ => {
            Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("NOT FOUND".into())
            .unwrap())
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(router))
    });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
