# tsidscan

BS,CSのトランスポンダに含まれるTSID一覧を取得するプログラムです。

BS帯域再編（トランスポンダ間の移動）に伴い、録画コマンドのチャンネル設定ファイルを修正する必要が出てきます。変更点を確認し手作業で修正する作業が意外と煩雑なことから可能な範囲で自動化することを目的としています。

動作確認環境は以下のとおりです。

* Ubuntu 22.04
* python 3.10.12
* DTV02-1T1S-U (Aなし初期型)
* PX-M1UR

TSIDの取得は、DTV02-1T1S-Uに搭載されているTC90532の機能を使用しています。そのため、BS放送が受信できる状態のDTV02-1T1S-U、もしくは、ハードウェア構成が同じデバイスが必要です。

## インストール

### Linux

```console
git clone https://github.com/hendecarows/tsidscan.git
cd tsidscan
sudo cp 99-digibest.rules /etc/udev/rule.d/
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

動作確認はLinux環境のみです。

## 使用方法

### TSID一覧の作成

BS,CS放送が受信可能なDTV02-1T1S-Uを接続し、BS,CSのトランスポンダに含まれるTSID一覧をJSON形式で保存します。

```console
./tsidscan.py tsids.json
```

PX-M1URを使用する場合、`--device`を指定するか、PID(0x0854)を直接指定します。

```console
./tsidscan.py --device m1ur tsids.json
```

```console
./tsidscan.py --pid 0x0854 tsids.json
```

### チャンネル設定ファイルの作成

次に、TSID一覧の作成で作成したJSON形式から録画コマンドのチャンネル設定ファイルに変換します。

* libdvbv5形式

```console
./chconfmake.py --format dvbv5 tsids.json dvbv5_channels_isdbs.conf
```

* [BonDriver_DVB.conf][link_bdpl]形式

`#ISDB_S`部分のみです。

```console
./chconfmake.py --format bondvb tsids.json bondvb.txt
```

* [BonDriver_LinuxPT.conf][link_bdpl]形式

`#ISDB_S`部分のみです。

```console
./chconfmake.py --format bonpt tsids.json bondvb.txt
```

* [BonDriver_LinuxPTX.ini][link_bonptx]形式

`[Space.BS.Channel]`部分のみです。

```console
./chconfmake.py --format bonptx tsids.json bonptx.txt
```

* [BonDriver_PX4-S.ChSet.txt][link_bonpx4]形式

`[BS]`部分のみです。

```console
./chconfmake.py --format bonpx4 tsids.json bonpx4.txt
```

* TSIDの除外

移動前のTSIDはBS帯域再編（トランスポンダ間の移動）後直ぐに削除される訳でなく、TSID一覧に含まれていることがあります。
その場合は`--ignore`オプションで不要なTSIDを除外して下さい。

```console
./chconfmake.py --format bonptx --ignore 16529,18099,18130 tsids.json bonptx.txt
```

[link_bdpl]: https://github.com/u-n-k-n-o-w-n/BonDriverProxy_Linux
[link_bonptx]: https://github.com/hendecarows/BonDriver_LinuxPTX
[link_bonpx4]: https://github.com/nns779/px4_drv