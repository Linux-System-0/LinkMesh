// 临时诊断工具：用指定公钥向服务器发送 KEYQUERY，打印响应中的服务器公钥（server_ik_x）。
// 用法：cargo run --example keyquery_probe -- <server_ip:port> <pubkey_b64>

use base64::Engine as _;
use linkmesh_client::connection::fetch_server_key_info;
use linkmesh_client::log::Logger;
use linkmesh_shared::crypto::parse_public_key;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ep: std::net::SocketAddr = args
        .get(1)
        .expect("用法: keyquery_probe <ip:port> <pubkey_b64>")
        .parse()
        .expect("地址解析失败");
    let pub_b64 = args.get(2).expect("缺少公钥").as_str();
    let pubkey = match parse_public_key(pub_b64) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("公钥解析失败: {e}");
            std::process::exit(1);
        }
    };
    let log = Logger::new("/tmp/keyquery_probe.log");
    match fetch_server_key_info(ep, &pubkey, &log).await {
        Ok(info) => {
            println!("OK pubkey={}", base64::engine::general_purpose::STANDARD.encode(info.pubkey));
            println!("MESH={}", info.mesh);
        }
        Err(e) => println!("ERROR: {e}"),
    }
}
