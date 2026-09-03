# 非目標

この package は次を行いません。

- 一般的な PKI path building、AIA 取得、OS trust store、CRL、OCSP
- TLS layer の mTLS 検証の置き換え
- RSA、Ed25519、P-256 以外の curve、algorithm negotiation
- 任意の RFC 9421 component や複数 signature
- method、target URI、content digest 以外の request header 保護
- body の streaming 署名・検証
- challenge の一回限りの消費や replay database
- 証明書発行、秘密鍵保存、rotation、recovery
- Browser Grant、Cookie、session、authorization、管理画面への引き継ぎ
- HTTP response や status code の生成

ステートレス challenge は期限内に再利用できます。exactly-once が必要な
application は、返却された `challengeId` を保存し一回限りで消費してください。
Browser Grant 等は署名検証成功後の Worker application 処理として残します。
