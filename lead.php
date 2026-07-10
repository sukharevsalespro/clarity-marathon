<?php
/**
 * lead.php — приём заявок с формы лендинга «Ясность мышления».
 * Пишет лид в leads.csv (рядом, закрыт от веба через .htaccess) и шлёт в Telegram-группу.
 * Форма шлёт POST (FormData, no-cors) с полями: product, name, phone, email,
 * tariff_id, tariff_name, tariff_price, payment_url, source_page, utm_*.
 */

// Секреты (токен бота, chat_id) — в lead-secrets.php рядом, он НЕ в git (см. .gitignore)
require __DIR__ . '/lead-secrets.php'; // определяет TG_TOKEN и TG_CHAT_ID
const CSV_FILE = __DIR__ . '/leads.csv';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'POST only']);
    exit;
}

$fields = ['product', 'name', 'phone', 'email', 'tariff_id', 'tariff_name', 'tariff_price',
           'payment_url', 'source_page', 'utm_source', 'utm_campaign', 'utm_content'];
$data = [];
foreach ($fields as $f) {
    $data[$f] = mb_substr(trim((string)($_POST[$f] ?? '')), 0, 500);
}
$data['created_at'] = date('c');
$data['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';

// примитивный анти-спам: имя и контакт обязательны
if ($data['name'] === '' || ($data['phone'] === '' && $data['email'] === '')) {
    http_response_code(422);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'empty lead']);
    exit;
}

// CSV-журнал (создаём с заголовком при первом лиде)
$isNew = !file_exists(CSV_FILE);
$fh = fopen(CSV_FILE, 'a');
if ($fh) {
    if (flock($fh, LOCK_EX)) {
        if ($isNew) {
            fputcsv($fh, array_merge(['created_at', 'ip'], $fields));
        }
        fputcsv($fh, array_merge([$data['created_at'], $data['ip']], array_map(fn($f) => $data[$f], $fields)));
        flock($fh, LOCK_UN);
    }
    fclose($fh);
}

// Telegram (HTML-разметка: жирный, моноширинные контакты для копирования одним тапом)
$esc = fn($v) => htmlspecialchars($v, ENT_QUOTES, 'UTF-8');

$tariffEmoji = ['solo' => '🌱', 'guide' => '🧭', 'vip' => '👑'][$data['tariff_id']] ?? '💎';
$contact = $data['phone'];
// @username → кликабельная ссылка на профиль
$contactHtml = $contact === '' ? '—'
    : (preg_match('/^@([A-Za-z0-9_]{4,})$/', $contact, $m)
        ? '<a href="https://t.me/' . $m[1] . '">' . $esc($contact) . '</a>'
        : '<code>' . $esc($contact) . '</code>');

$lines = [
    '🔔 <b>Новая заявка</b> — марафон «Ясность мышления»',
    '',
    $tariffEmoji . ' <b>' . $esc($data['tariff_name'] ?: 'Тариф не указан') . '</b> · <b>' . $esc($data['tariff_price'] ?: '—') . '</b>',
    '',
    '👤 ' . $esc($data['name']),
    '📱 ' . $contactHtml,
    '📧 ' . ($data['email'] !== '' ? '<code>' . $esc($data['email']) . '</code>' : '—'),
];
$meta = [];
if ($data['utm_source'] !== '' || $data['utm_campaign'] !== '') {
    $meta[] = 'UTM: ' . $esc(trim($data['utm_source'] . ' / ' . $data['utm_campaign'], ' /'));
}
$meta[] = '⏰ ' . date('d.m.Y H:i') . ' MSK';
$lines[] = '';
$lines[] = '<blockquote>' . implode("\n", $meta) . '</blockquote>';

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

header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok' => true]);
