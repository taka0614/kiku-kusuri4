<?php
/**
 * inc/session_bootstrap.php
 *
 * コンタクトフォーム関連の全PHPエンドポイント（csrf_token.php, contact.php）で
 * 共通利用するセッション初期化処理。
 *
 * ここでCookie属性（secure/httponly/samesiteなど）を一箇所に集約することで、
 * ファイルごとに設定がズレてCSRF検証が失敗する事故を防ぐ。
 *
 * 【使い方】呼び出し元の先頭で必ず以下の順序で読み込むこと:
 *
 *   define('APP_BOOTSTRAP', true);
 *   require __DIR__ . '/inc/session_bootstrap.php';
 *
 * 【重要】このファイルはWebから直接リクエストされても処理が実行されないよう、
 * APP_BOOTSTRAP定数の定義を必須にしている。可能であればドキュメントルート外
 * （例: /inc を公開ディレクトリの外）に配置するか、.htaccessで直接アクセスを
 * 拒否する設定を追加することを推奨する。
 */

declare(strict_types=1);

if (!defined('APP_BOOTSTRAP')) {
    http_response_code(403);
    exit('Forbidden');
}

// 文字コード関連の内部エンコーディングを明示し、mb_encode_mimeheader等の挙動を安定させる。
mb_internal_encoding('UTF-8');

// 二重require対策（同一リクエスト内で複数回読み込まれても安全にする）
if (session_status() === PHP_SESSION_ACTIVE) {
    return;
}

// Session Fixation対策: サーバーが発行していない未知のセッションIDを拒否する
ini_set('session.use_strict_mode', '1');

// リバースプロキシ配下（X-Forwarded-Proto）も含めてHTTPS接続かどうかを判定
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['SERVER_PORT'] ?? '') === '443')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

session_set_cookie_params([
    'lifetime' => 0,       // ブラウザを閉じたら破棄されるセッションCookie
    'path' => '/',         // サイト全体でCookieを共有
    'domain' => '',        // アクセス中のホスト名にのみ紐付け（サブドメイン間共有はしない）
    'secure' => $isHttps,  // HTTPS接続時のみCookie送信
    'httponly' => true,    // JavaScriptからCookieを読めなくする（XSS対策）
    'samesite' => 'Lax',   // クロスサイトリクエストではCookieを送らない（CSRF対策の補助）
]);

session_start();
