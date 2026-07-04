# timeproof

可信时钟 + Ed25519 离线 License 验证。

不信任系统时钟，通过 TLS 从 HTTPS 站点（baidu / aliyun）获取响应头 `Date` 字段做过期验证。CA 使用 webpki-root-certs（Mozilla 内置根证书），不信任系统 CA。

## 快速开始

```toml
[dependencies]
timeproof = { git = "https://github.com/xutianyi1999/timeproof" }
```

## API

```rust
// 生成密钥对
let (sk, vk) = timeproof::generate_keypair();

// 签发 License（exp 为 Unix 秒级时间戳）
let license = timeproof::create_license(&sk, 1893456000);

// 验证 License（内部走 HTTPS 取真实时间）
match timeproof::verify_license(&vk, &license).await {
    Ok(info) => println!("OK: exp={}", info.exp),
    Err(e) => eprintln!("DENIED: {e}"),
}
```


