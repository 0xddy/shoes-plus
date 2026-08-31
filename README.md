<div align="center">

# shoes-plus

**面向生产环境维护的 Shoes 分支**

[![CI](https://github.com/0xddy/shoes-plus/actions/workflows/test.yml/badge.svg)](https://github.com/0xddy/shoes-plus/actions/workflows/test.yml)

[上游项目](https://github.com/cfal/shoes) · [配置文档](CONFIG.md) · [示例](examples) · [MIT License](LICENSE)

</div>

基于 [cfal/shoes](https://github.com/cfal/shoes)，保留轻量代理内核；控制面、重连和进程守护交给上层。

## 支持

| 类别 | 内容 |
|---|---|
| 协议 | HTTP(S)、SOCKS5、VMess、VLESS、Trojan、Shadowsocks、Snell、Hysteria2、TUIC、AnyTLS、NaiveProxy |
| 传输 | TCP、QUIC、TLS、Reality、Vision、WebSocket、ShadowTLS、H2MUX、UoT、XUDP |
| 能力 | 规则路由、DNS、代理链、热重载、动态用户、流量计量、TUN |

## 构建

```bash
git clone https://github.com/0xddy/shoes-plus.git
cd shoes-plus
cargo build --release --locked
```

## 运行

```yaml
# config.yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
```

```bash
./target/release/shoes --dry-run config.yaml
./target/release/shoes config.yaml
```

完整配置见 [CONFIG.md](CONFIG.md)，更多用法见 [examples](examples)。

## 检查

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked --no-deps
cargo test --all-targets --locked
```

## License

[MIT](LICENSE)，保留上游项目原始版权声明。
