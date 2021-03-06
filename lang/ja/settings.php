<?php

$lang['freqBorder'] = 'Frequency Score（累計報告回数）チェック時の、スパム判定のボーダーライン<br>スコアが設定値以上の場合に、当該訪問者をスパムとして認識します。設定値が0の場合、プラグインではFrequency Scoreのチェックを行いません。<br>こちらはプラグイン使用時の標準的な基準値となりますが、このプラグインと連携する一部機能の中には、こちらより厳しい、あるいは緩い基準値を使用するものもあるでしょう。';
$lang['confidenceBorder'] = 'Confidence Score（当該訪問者がスパムである可能性）チェック時の、スパム判定のボーダーライン<br>スコアが設定値以上の場合に、当該訪問者をスパムとして認識します。設定値が0の場合、プラグインではConfidence Scoreのチェックを行いません。<br>こちらはプラグイン使用時の標準的な基準値となりますが、このプラグインと連携する一部機能の中には、こちらより厳しい、あるいは緩い基準値を使用するものもあるでしょう。';
$lang['protectRegFreq'] = '訪問者のIPアドレス及び入力されたフルネームとメールアドレスのFrequency Scoreをチェックしてユーザー登録フォームを保護するかどうか<br>"0"を入力するとチェックを行いません。0でない場合はチェックします。このオプション特有の基準値を指定出来ます。"-1"を入力すると、上の設定"freqBorder"で指定した値が基準値となりますが、0より大きい値を入力すると、それが基準値となります。';
$lang['protectRegConf'] = '訪問者のIPアドレス及び入力されたフルネームとメールアドレスのConfidence Scoreをチェックしてユーザー登録フォームを保護するかどうか<br>"0"を入力するとチェックを行いません。0でない場合はチェックします。このオプション特有の基準値を指定出来ます。"-1"を入力すると、上の設定"confidenceBorder"で指定した値が基準値となりますが、0より大きい値（100以下）を入力すると、それが基準値となります。';
$lang['preventNuisanceReg'] = 'スパムと思われるユーザー登録リクエストがあった後の、登録フォームの保護持続期間（分単位、0を設定すると無効に出来ます）<br>同じIPアドレスから短期間に連続してスパムっぽいユーザー登録リクエストが送信されるのを防ぎます。ユーザー登録フォームにてスパムっぽい登録リクエストがあった場合、そのリクエストの送信元IPアドレスを保持する一時ファイルを作成します。一時ファイルに保持されているIPアドレスと同じアドレスからユーザー登録のリクエストが送られようとしていて、尚且つ保護期間を経過していない場合、そのリクエストは自動的にブロックされます。';
$lang['protectEditFreq'] = '訪問者のIPアドレスのFrequency Scoreをチェックして編集フォームを保護するかどうか<br>"0"を入力するとチェックを行いません。0でない場合はチェックします。このオプション特有の基準値を指定出来ます。"-1"を入力すると、上の設定"freqBorder"で指定した値が基準値となりますが、0より大きい値を入力すると、それが基準値となります。';
$lang['protectEditConf'] = '訪問者のIPアドレスのConfidence Scoreをチェックして編集フォームを保護するかどうか<br>"0"を入力するとチェックを行いません。0でない場合はチェックします。このオプション特有の基準値を指定出来ます。"-1"を入力すると、上の設定"confidenceBorder"で指定した値が基準値となりますが、0より大きい値（100以下）を入力すると、それが基準値となります。';
$lang['accessRefusalFreq'] = '訪問者のIPアドレスのFrequency Scoreをチェックしてスパマーだと判定された場合に、アクセス拒否を行うかどうか<br>"0"を入力するとチェックを行いません。0でない場合はチェックします。このオプション特有の基準値を指定出来ます。"-1"を入力すると、上の設定"freqBorder"で指定した値が基準値となりますが、0より大きい値を入力すると、それが基準値となります。';
$lang['accessRefusalConf'] = '訪問者のIPアドレスのConfidence Scoreをチェックしてスパマーだと判定された場合に、アクセス拒否を行うかどうか<br>"0"を入力するとチェックを行いません。0でない場合はチェックします。このオプション特有の基準値を指定出来ます。"-1"を入力すると、上の設定"confidenceBorder"で指定した値が基準値となりますが、0より大きい値（100以下）を入力すると、それが基準値となります。.';
$lang['skipMgAndSp'] = 'ログインユーザーやマネージャー、スーパーユーザーをチェックしないかどうか（設定「<a href="#config___manager">manager</a>」「<a href="#config___superuser">superuser</a>」参照）';
$lang['ipWhitelist'] = 'IPアドレスのホワイトリスト<br>これらのIPアドレスからのアクセスや投稿についてはチェックを行いません。<br>対象のIPを、1行ごとに1つ入力して下さい。<br>次のワイルドカードが使えます。<br>? = 1文字<br>* = 1文字以上<br><br>例："123.456.???.123"⇒123.456.789.123 など（123.456.78.123は除外されません）<br>例："123.*.789.123"⇒123.456.789.123、123.9.789.123 など';
$lang['emailWhitelist'] = 'Eメールアドレスのホワイトリスト<br>これらのEメールアドレスからのアクセスや投稿についてはチェックを行いません。<br>対象のアドレスを、1行ごとに1つ入力して下さい。国際化ドメイン名（IDN）をサポートしています。<br>次のワイルドカードが使えます。<br> ? = 1文字（文字種不問）<br>* = 1文字以上（文字種不問）<br>! = 1文字（半角数字のみ）<br>~ = 1文字以上（半角数字のみ）<br><br>例："???@example.com"⇒123@example.com など（4567@example.comは除外されません）<br>例："*@example.com"⇒hogehoge@example.com、blahblah1234@example.com など';
$lang['nameWhitelist'] = 'ユーザー名のホワイトリスト（ユーザーIDでない）<br>これらの名前のもとでなされたアクセスや投稿についてはチェックを行いません。<br>対象の名前を、1行ごとに1つ入力して下さい。<br>次のワイルドカードが使えます。<br> ? = 1文字（文字種不問）<br>* = 1文字以上（文字種不問）<br>! = 1文字（半角数字のみ）<br>~ = 1文字以上（半角数字のみ） <br><br>例："???Spammer"⇒FunSpammer など（IntelligentSpammerは除外されません）<br>例："*Socks"⇒RedSocks、BlackSocks など';
$lang['userWhitelist'] = 'ユーザー・ユーザーグループのホワイトリスト（フルネームでない）<br>これらのユーザー及びユーザーグループに属するユーザーからのアクセスや投稿についてはチェックを行いません。<br>対象のユーザーあるいはユーザーグループを、半角カンマ区切りで入力して下さい。';
$lang['logPlace'] = 'スパム検出時にログを保存する場所<br>ログを保存するファイルパス（ディレクトリとファイル名）を入力して下さい。空欄の場合は、ログ保存を行いません。<br>必要に応じてファイルの抽出や削除を行って下さい。<br>指定例：<code>/yourserver/log/sfslogfile.txt</code>';
$lang['reportAPI'] = 'addToDatabase関数を通してレポートする際のAPIキー（外部に漏れてはいけません）<br>空欄の場合、addToDatabase関数は働きません。';
$lang['skipMgAndSp_o_0']  ='全員チェックする';
$lang['skipMgAndSp_o_sp']  ='スーパーユーザーをスキップする';
$lang['skipMgAndSp_o_mg']    ='マネージャー（スーパーユーザー含む）をスキップする';
$lang['skipMgAndSp_o_user']    ='ログインユーザー（ﾏﾈ-ｼﾞｬ-・ｽ-ﾊﾟ-ﾕ-ｻﾞ-含む）をスキップする';
