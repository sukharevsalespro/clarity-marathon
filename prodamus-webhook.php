<?php
/**
 * prodamus-webhook.php — уведомления об оплате от Продамуса (payform.ru).
 * В кабинете Продамуса в настройках платёжной страницы указать URL уведомлений:
 *   https://katipa-art.ru/prodamus-webhook.php
 * Продамус шлёт POST c данными платежа и подписью в заголовке Sign (HMAC-SHA256 по их
 * алгоритму: убрать sign, все значения в строки, рекурсивный ksort, json_encode).
 * Валидная оплата → сообщение в Telegram-группу + строка в payments.csv (закрыт .htaccess).
 * Ответ 200 обязателен, иначе Продамус ретраит.
 */

require __DIR__ . '/lead-secrets.php'; // TG_TOKEN, TG_CHAT_ID, PRODAMUS_SECRET
const PAYMENTS_CSV = __DIR__ . '/payments.csv';

function prodamus_sign(array $data, string $key): string
{
    unset($data['sign']);
    array_walk_recursive($data, function (&$v) { $v = (string)$v; });
    $sortRecursive = function (array &$a) use (&$sortRecursive) {
        ksort($a, SORT_REGULAR);
        foreach ($a as &$v) {
            if (is_array($v)) $sortRecursive($v);
        }
    };
    $sortRecursive($data);
    return hash_hmac('sha256', json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $key);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('POST only');
}

$sign = $_SERVER['HTTP_SIGN'] ?? ($_POST['sign'] ?? '');
if ($sign === '' || !hash_equals(prodamus_sign($_POST, PRODAMUS_SECRET), $sign)) {
    http_response_code(403);
    exit('bad sign');
}

$get = fn($k) => mb_substr(trim((string)($_POST[$k] ?? '')), 0, 300);
$status  = $get('payment_status');
$sum     = $get('sum');
$orderNum = $get('order_num') ?: $get('order_id');
$phone   = $get('customer_phone');
$email   = $get('customer_email');
$product = '';
if (!empty($_POST['products']) && is_array($_POST['products'])) {
    $first = reset($_POST['products']);
    if (is_array($first)) $product = mb_substr(trim((string)($first['name'] ?? '')), 0, 300);
}

// журнал всех уведомлений (и успехов, и отказов)
$isNew = !file_exists(PAYMENTS_CSV);
$fh = fopen(PAYMENTS_CSV, 'a');
if ($fh) {
    if (flock($fh, LOCK_EX)) {
        if ($isNew) fputcsv($fh, ['received_at', 'status', 'sum', 'order', 'product', 'phone', 'email']);
        fputcsv($fh, [date('c'), $status, $sum, $orderNum, $product, $phone, $email]);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
}

$esc = fn($v) => htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
$ok = ($status === 'success');
$lines = [
    ($ok ? '💰 <b>Оплата получена</b>' : '⚠️ <b>Платёж: ' . $esc($status ?: 'статус неизвестен') . '</b>') . ' — «Ясность мышления»',
    '',
    '📦 ' . ($product !== '' ? $esc($product) : '—'),
    '💵 <b>' . $esc($sum) . ' ₽</b>',
    '📱 ' . ($phone !== '' ? '<code>' . $esc($phone) . '</code>' : '—'),
    '📧 ' . ($email !== '' ? '<code>' . $esc($email) . '</code>' : '—'),
    '',
    '<blockquote>Заказ: ' . $esc($orderNum ?: '—') . "\n⏰ " . date('d.m.Y H:i') . ' MSK</blockquote>',
];

$ch = curl_init('https://api.telegram.org/bot' . TG_TOKEN . '/sendMessage');
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_POSTFIELDS => http_build_query([
        'chat_id' => TG_CHAT_ID,
        'parse_mode' => 'HTML',
        'text' => implode("\n", $lines),
        'disable_web_page_preview' => true,
    ]),
]);
curl_exec($ch);
curl_close($ch);

http_response_code(200);
echo 'success';
