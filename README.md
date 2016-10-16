beacon2json
===========

# なにこれ
IEEE802.11 Beacon フレームから必要そうな情報を JSON 化するやつ

# 取り出す情報
- timestamp
  - フレームキャプチャ日時
- source
  - Beacon 発信MACアドレス
- ssid
  - SSID
- freq
  - 周波数
- signal
  - -0 - -100 dB
- interval
  - Beacon 発信間隔(単位TU (1024 microseconds))

# インストール

# つかいかた
```bash
beacon2json -r beacon-capture.pcap > beacon-summary.json
```
