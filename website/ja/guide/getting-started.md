# はじめに

mqvpn は MASQUE CONNECT-IP (RFC 9484) と、Multipath QUIC をベースとしたL3 マルチパス VPN です。

## インストール

### サーバー

#### Debian / Ubuntu（deb パッケージ）

`mqvpn` deb にはクライアントとサーバーの両方で使う VPN プログラムが含まれ、`mqvpn-server` deb はサーバーのサービス・NAT 設定・初回設定を追加します。[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から同じバージョンの `mqvpn` と `mqvpn-server` の deb をダウンロードし、両方をインストールします。

```bash
# 最新リリースのバージョンと、このマシンのアーキテクチャ
V=$(curl -fsSL https://api.github.com/repos/mp0rta/mqvpn/releases/latest \
  | grep -Po '"tag_name": "v\K[^"]+')
A=$(dpkg --print-architecture)
B=https://github.com/mp0rta/mqvpn/releases/download/v$V
curl -fLO $B/mqvpn_${V}_$A.deb -fLO $B/mqvpn-server_${V}_$A.deb
sudo apt install ./mqvpn_${V}_$A.deb ./mqvpn-server_${V}_$A.deb
```

インストール時に証明書・認証キー・設定ファイルを生成し、サーバーを起動して OS 起動時の自動起動も登録します。証明書や設定ファイルがすでにある場合は、そのまま使います。生成される設定ではサーバー側のハイブリッドモードと reorder バッファが有効になっており、クライアント側でも有効にしたときだけ動作します。`AllowClientScheduler = true` も設定されるので、クライアントは自分のダウンロード方向のスケジューラを指定できます。

インストール時に認証キーと、QR コード付きの接続リンクが表示されます（[クイックスタート](#クイックスタート)を参照）。あとから `sudo mqvpn-server-info` で再表示できます。

インストール中には、クライアント用サブネットは、デフォルトの `10.0.0.0/24` がサーバーのネットワークと重なる場合のみ、ポートは UDP 443 がすでに使用中の場合のみ尋ねます。自動化などで事前に値を指定するには、次のようにします。

```bash
echo 'mqvpn-server mqvpn-server/subnet string 10.8.0.0/24' | sudo debconf-set-selections
sudo env MQVPN_PORT=10020 apt install ./mqvpn_${V}_$A.deb ./mqvpn-server_${V}_$A.deb
```

これらの値は `/etc/mqvpn/server.conf` を新しく生成するときだけ使われます。稼働中のサーバーの設定を変えるには、`/etc/mqvpn/server.conf` を編集して `sudo systemctl restart mqvpn-server` を実行します。

`sudo apt remove mqvpn-server` はサーバーを停止し、`/etc/mqvpn` は残します。`sudo apt purge mqvpn-server` は生成された設定ファイル・認証キー・証明書も削除するため、すべてのクライアントに新しい認証キーが必要になります。自分で作成したファイルは削除されません。詳細は `/usr/share/doc/mqvpn-server/README.Debian` を参照してください。

::: tip 0.19.2 以前からのアップグレード
サーバー用のファイルは `mqvpn` deb から新しい `mqvpn-server` deb に移りました。両方の deb をまとめてインストールしてください。`/etc/mqvpn` の設定はそのまま残ります。以前に install.sh を使っていた場合は、先に `--uninstall` を付けて実行してください（`/etc/mqvpn` は残ります）。
:::

#### その他の Linux ディストリビューション（インストールスクリプト）

以下を実行すると、バイナリを `/usr/local` にインストールし、deb と同じ証明書・認証キー・設定ファイルを生成します。

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh | sudo bash
```

`--start` を付けると、サーバーの起動と OS 起動時の自動起動登録も同時に行います。

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start
```

ポートやサブネットのカスタマイズもオプションで指定できます。

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start --port 10020 --subnet 10.8.0.0/24
```

スクリプトは `mqvpn-server-info` もインストールし、最後に実行します。そのため deb と同じく `sudo mqvpn-server-info` が使えます。アンインストールするには `--uninstall` を付けて再実行します（`--purge` で設定ファイルも削除）。

::: warning
どちらのインストール方法でも、サーバーに証明書がない場合は自己署名証明書が生成されます。その証明書のままでも、リンクを使えば安全に接続できます。リンクにサーバーの公開鍵の指紋（「ピン」）が入っていて、クライアントが本物のサーバーかどうかを見分けられるからです。ドメイン名でサーバーを運用したい場合は、Let's Encrypt などの認証局の証明書に置き換えてください。どちらも正式な運用方法です。`--insecure` はサーバーの確認を一切行わないので、テスト専用です。クライアントの設定ファイルに `Insecure = true` が残っている場合は、ピンやリンクを使うときにその行を削除してください。deb はすでにある証明書をそのまま使います。
`--cert` (設定ファイルでは `Cert` / `cert_file`) には fullchain (Let's Encrypt では `fullchain.pem`) を指定してください。クライアントは足りない中間証明書を取りに行きません。
:::

### クライアント（Debian / Ubuntu）

[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `mqvpn` の deb をダウンロードしてインストールします。

```bash
# 最新リリースのバージョンと、このマシンのアーキテクチャ
V=$(curl -fsSL https://api.github.com/repos/mp0rta/mqvpn/releases/latest \
  | grep -Po '"tag_name": "v\K[^"]+')
A=$(dpkg --print-architecture)
curl -fLO https://github.com/mp0rta/mqvpn/releases/download/v$V/mqvpn_${V}_$A.deb
sudo apt install ./mqvpn_${V}_$A.deb
```

### Windows クライアント

Windows amd64 / arm64 向けにビルド済みバイナリを配布しています。[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `mqvpn_<VERSION>_windows_<ARCH>.zip` をダウンロードし、展開して同梱の `README.txt` に従ってください（管理者 PowerShell 必須）。

### macOS クライアント

Apple silicon (arm64) 向けにビルド済みバイナリを配布しています。[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `mqvpn_<VERSION>_darwin_arm64.tar.gz` をダウンロードし、展開して同梱の `README.txt` に従ってください（sudo 必須）。

### ソースからビルド

ソースからビルドする場合は[ビルド](./building)を参照してください。

## クイックスタート

サーバーで接続リンクを表示します。

```bash
sudo mqvpn-server-info
```

リンク（`mqvpn://…`）とその QR コードが表示されます（QR コードは端末で実行したときだけ描画され、出力をパイプで渡したりファイルに保存したりした場合は QR コードが省かれます）。端末では、クライアントで実行するコマンドも表示されます。リンクにはサーバーのアドレス、認証キー、ピンが入っています。クライアントでは、このリンクを使って接続します。

```bash
sudo mqvpn --connect 'mqvpn://203.0.113.5:443?key=YOUR_KEY&pin=YOUR_PIN'
```

リンクには `?` や `&` が含まれるので、シングルクォートで囲んでください。Windows のコマンドプロンプトでは、代わりにダブルクォートで囲みます。

マルチパス（複数インターフェース）：

```bash
sudo mqvpn --connect 'mqvpn://203.0.113.5:443?key=YOUR_KEY&pin=YOUR_PIN' \
    --path eth0 --path wlan0
```

DNS オーバーライド付き（DNS リーク防止）：

```bash
sudo mqvpn --connect 'mqvpn://203.0.113.5:443?key=YOUR_KEY&pin=YOUR_PIN' \
    --dns 1.1.1.1 --dns 8.8.8.8
```

`--connect` は `--kill-switch` など他のクライアントオプションや、`--config FILE` と組み合わせられます（その場合、設定ファイルのサーバーアドレス・キー・ピンはリンクの値に置き換わります）。`--server`・`--auth-key`・`--pin`・`--insecure`・`--mode server` とは併用できません。`--connect` を `--config` と一緒に使うと、設定ファイルの `Insecure` と `ServerName` は使われません。Linux・Windows・macOS のクライアントで使えます。

::: warning
リンクと QR コードには認証キーが入っています。パスワードと同じように扱ってください。スクリーンショットを公開せず、リンクを知っていれば誰でも接続できることに注意してください。コマンドラインに打ち込んだリンクは、ほかの秘密情報と同じくシェルの履歴にも残り、クライアントの実行中は、リンク（つまり認証キー）が同じコンピューターのほかのユーザーにもプロセス一覧で見えます。`--auth-key` と同じです。リンクは、サーバーの管理者から信頼できる経路で受け取ってください。途中で書き換えられたリンクを使うと、別のサーバーに接続してしまいます。
:::

### リンクについて

- インストールで生成された証明書を使っている場合、リンクには `pin` が入ります。クライアントはその鍵を持つサーバーだけを信頼し、証明書の名前・有効期限・発行元は確認しないので、証明書の有効期限は関係ありません。同じ鍵で証明書を再発行した場合も、リンクはそのまま使えます。サーバーの鍵を入れ替えたときは、クライアントに新しいリンクが必要です。
- Let's Encrypt などの認証局の証明書を使っている場合、リンクに `pin` は入りません。ホストは証明書の最初の DNS 名（または `--host` で指定した名前）になり、クライアントは通常どおり証明書を検証します。
- リンクのアドレスはサーバー自身のアドレスです。それがプライベートアドレスの場合（AWS・GCP などのクラウドや、家庭用ルーターの内側）、`mqvpn-server-info` は外部サービス（`ifconfig.me`）にサーバーの公開アドレスを 1 回だけ問い合わせます。サーバーのインターフェースが公開アドレスを持つ場合（多くの VPS）は、何も問い合わせません。アドレスを自分で指定して問い合わせを避けるには `sudo mqvpn-server-info --host ADDR[:PORT]` を使います。問い合わせに失敗すると、この方法を案内するヒントが表示されます。
- リンクに入るのは、サーバー共通の認証キー（`[Auth] Key`）です。ユーザーごとに鍵を分けている場合（`User = NAME:KEY`）は、`sudo mqvpn-server-info --user NAME` でユーザーごとのリンクを作れます。ピンはどのユーザーでも同じです。対象は設定ファイルに書かれたユーザーで、コントロール API だけで追加したユーザーは対象外です。
- QR コードは、リンクを持ち運ぶための手段です。QR リーダーで読み取ると `mqvpn://…` の文字列が表示されます。Android / iOS アプリはまだ QR コードを読み取れません。

### リンクを使わない場合

リンクは近道です。サーバーアドレスと認証キーを自分で指定する方法も使えます。

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --pin YOUR_PIN
```

`--pin`（設定ファイルでは `[Server]` セクションの `Pin`）はリンクに入っているピンです。サーバーが認証局の証明書を使っている場合は省略してください。`--insecure`（または `Insecure = true`）は「サーバーを一切確認しない」という意味で、テスト専用です。ピンとは併用できず、両方を指定すると mqvpn は起動しません。

::: tip
`--path` を指定しない場合、クライアントはデフォルトインターフェースを使います（シングルパス）。マルチパスには2つ以上の `--path` が必要です。詳しくは[マルチパス](./multipath)を参照してください。
:::

::: warning
サーバーは UDP ポート（デフォルト: 443）を開放する必要があります。クライアントのすべてのトラフィックはトンネル経由でルーティングされます。
:::

## 認証キーの生成

```bash
mqvpn --genkey
```

install.sh や `start_server.sh` を使う場合は自動生成されます。

## CLI リファレンス

```
mqvpn --config PATH
mqvpn --mode client|server [options]

  --server HOST:PORT     サーバーアドレス（クライアント、IPv6 は `[2001:db8::1]:443` 形式）
  --connect LINK         mqvpn:// リンクで接続（クライアント）
  --pin PIN              サーバー公開鍵のピン、43 文字（クライアント）
  --show-link            接続リンクと QR コードを表示して終了（サーバー）
  --host ADDR[:PORT]     クライアントがこのサーバーに接続するアドレス（--show-link と併用）
  --link-user NAME       このユーザーの鍵をリンクに入れる（--show-link と併用）
  --path IFACE           マルチパスインターフェース（複数指定可）
  --auth-key KEY         PSK 認証
  --user NAME:KEY[:IP]   ユーザー個別の PSK。IP でそのユーザーの VPN アドレスを固定（複数指定可、サーバー）
  --dns ADDR             DNS サーバー（複数指定可）
  --tls-server-name NAME TLS SNI / 証明書検証名（クライアント）
  --insecure             信頼されていない証明書を受け入れる（テスト用）
  --tun-name NAME        TUN デバイス名（デフォルト: mqvpn0）
  --listen BIND:PORT     リッスンアドレス（サーバー、デフォルト: 0.0.0.0:443）
  --subnet CIDR          クライアント IPv4 プール（サーバー）
  --subnet6 CIDR         クライアント IPv6 プール（サーバー）
  --cert PATH            TLS 証明書（サーバー）
  --key PATH             TLS 秘密鍵（サーバー）
  --scheduler SCHED      マルチパススケジューラ: minrtt|wlb|wlb_udp_pin|backup_fec
                         （デフォルト: wlb）
  --cc ALGO              輻輳制御アルゴリズム: bbr2|bbr|cubic|none（デフォルト: bbr2）
  --mtu N                TUN MTU（1280-9000、デフォルト: auto）
  --path-mtu N           QUIC パケットのサイズを合わせる経路 MTU（1280-9000、デフォルト: 0）
  --pmtud                経路 MTU を探索する（両端で指定）。--path-mtu が上限になる
  --max-clients N        最大同時接続クライアント数（サーバー、デフォルト: 64）
  --control-port PORT    Control API の TCP ポート（サーバー）
  --control-addr ADDR    Control API のバインドアドレス（デフォルト: 127.0.0.1）
  --status               サーバーの稼働状況を Control API 経由で表示して終了
  --log-level LVL        ログレベル（debug|info|warn|error）
  --no-reconnect         自動再接続を無効化（クライアント）
  --kill-switch          VPN 外への通信を遮断（クライアント）
  --no-manage-routes     ホストのルーティングテーブルを変更しない（クライアント）
  --genkey               PSK を生成して終了
  --version              バージョンを表示して終了
  --help                 すべてのオプションを表示
```

`--config` を指定した場合、`--mode` は設定ファイル内容から自動判定されます。CLI 引数は設定ファイルの値を上書きします。

## 次のステップ

- [ビルド](./building) — Linux、Windows、Android でのソースからのビルド
- [設定](./configuration) — 設定ファイルリファレンス
- [マルチパス](./multipath) — マルチパスのセットアップとスケジューラオプション
