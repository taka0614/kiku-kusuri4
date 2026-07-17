<?php
/**
 * csrf_token.php
 * フロントエンド（静的HTML）がページ読み込み時にfetchで呼び出し、
 * コンタクトフォーム送信用のCSRFトークンを取得するためのエンドポイント。
 *
 * GETのみ許可。トークンはセッションに保存し、contact.php側で検証・使い捨てにする。
 */

declare(strict_types=1);

// contact.php / index側と同一のセッションCookie設定を共通ファイルから読み込む
define('APP_BOOTSTRAP', true);
require __DIR__ . '/inc/session_bootstrap.php';

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'method not allowed']);
    exit;
}

// 簡易Same-Origin確認（Originヘッダが送られてくる場合のみ検証）
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $originHost = parse_url($origin, PHP_URL_HOST);
    if ($originHost !== null && $host !== '' && strcasecmp($originHost, explode(':', $host)[0]) !== 0) {
        http_response_code(403);
        echo json_encode(['error' => 'invalid origin']);
        exit;
    }
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

echo json_encode(['csrf_token' => $_SESSION['csrf_token']], JSON_UNESCAPED_UNICODE);
