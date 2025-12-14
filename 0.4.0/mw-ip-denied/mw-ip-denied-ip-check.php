<?php
/**
 * MW IP Denied - IP checker (IPv4 / IPv6)
 *
 * GPL2.
 * ip_check_display.php を参考に、サーバヘッダ・外部グローバルIP確認サイト・
 * クライアントPOST値を統合してIPv4/IPv6を収集する。
 */

if ( ! function_exists( 'mw_ip_denied_session_start' ) ) {
function mw_ip_denied_session_start() {
if ( session_status() === PHP_SESSION_NONE ) {
@session_start();
}
}
}

if ( ! function_exists( 'mw_ip_denied_http_get' ) ) {
function mw_ip_denied_http_get( $url ) {
if ( function_exists( 'wp_remote_get' ) ) {
$res = wp_remote_get( $url, array( 'timeout' => 5, 'sslverify' => true ) );
if ( is_wp_error( $res ) ) return '';
$body = wp_remote_retrieve_body( $res );
return is_string( $body ) ? $body : '';
}
if ( function_exists( 'curl_init' ) ) {
$ch = curl_init( $url );
curl_setopt_array( $ch, array(
CURLOPT_RETURNTRANSFER => true,
CURLOPT_FOLLOWLOCATION => true,
CURLOPT_TIMEOUT => 5,
CURLOPT_SSL_VERIFYPEER => true,
CURLOPT_SSL_VERIFYHOST => 2,
) );
$body = curl_exec( $ch );
curl_close( $ch );
return $body ?: '';
}
$context = stream_context_create( array(
'http' => array( 'timeout' => 5 ),
'https' => array( 'timeout' => 5, 'verify_peer' => true, 'verify_peer_name' => true ),
) );
$body = @file_get_contents( $url, false, $context );
return $body === false ? '' : $body;
}
}

if ( ! function_exists( 'mw_ip_denied_add_ip' ) ) {
function mw_ip_denied_add_ip( array &$collected, $ip ) {
if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return;
$key = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 'ipv6' : 'ipv4';
if ( ! in_array( $ip, $collected[ $key ], true ) ) {
$collected[ $key ][] = $ip;
}
}
}

if ( ! function_exists( 'mw_ip_denied_collect_server_ips' ) ) {
function mw_ip_denied_collect_server_ips( array &$collected ) {
if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
mw_ip_denied_add_ip( $collected, $_SERVER['REMOTE_ADDR'] );
}
if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
$xff_list = array_map( 'trim', explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
foreach ( $xff_list as $i => $v ) {
mw_ip_denied_add_ip( $collected, $v );
}
}
if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
mw_ip_denied_add_ip( $collected, $_SERVER['HTTP_CF_CONNECTING_IP'] );
}
if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
mw_ip_denied_add_ip( $collected, $_SERVER['HTTP_X_REAL_IP'] );
}
}
}

if ( ! function_exists( 'mw_ip_denied_collect_client_post' ) ) {
function mw_ip_denied_collect_client_post( array &$collected ) {
if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
return;
}
if ( isset( $_POST['client_ip'] ) ) {
mw_ip_denied_add_ip( $collected, $_POST['client_ip'] );
}
if ( isset( $_POST['mw_ip_denied_client_ip'] ) ) {
mw_ip_denied_add_ip( $collected, $_POST['mw_ip_denied_client_ip'] );
}
}
}

if ( ! function_exists( 'mw_ip_denied_render_js_collector' ) ) {
function mw_ip_denied_render_js_collector() {
?>
<div id="mw-ip-denied-js-log" style="display:none;"></div>
<script>
(async function(){
    const log = (s)=>{ 
        const el = document.getElementById('mw-ip-denied-js-log');
        if(el) el.textContent += s + "\n"; 
    };
    const clientApis = [
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json",
        "https://ifconfig.co/json",
        "https://ident.me",
        "https://v6.ident.me",
        "https://ipinfo.io/ip"
    ];
    let found = false;
    for (const url of clientApis) {
        try {
            log("fetch " + url);
            const res = await fetch(url, {cache: "no-store"});
            let text = await res.text();
            let ip = "";
            try {
                const j = JSON.parse(text);
                if (j && j.ip) ip = j.ip;
            } catch(e){
                ip = text.trim();
            }
            if (ip) {
                log("found: " + ip + " from " + url);
                // 既に取得済みのIPと同じなら送信しない判定も入れたいが、
                // ここではシンプルに見つかったらPOSTしてリロードする
                const fd = new FormData();
                fd.append('mw_ip_denied_client_ip', ip);
                fd.append('source', url);
                
                await fetch(location.href, {
                    method: "POST",
                    body: fd
                });
                found = true;
            }
        } catch (e) {
            log("error: " + e);
        }
    }
    if (found) {
        log("done, reloading...");
        setTimeout(()=>location.reload(), 800);
    }
})();
</script>
<?php
}
}

if ( ! function_exists( 'mw_ip_denied_get_remote_ips' ) ) {
function mw_ip_denied_get_remote_ips() {
mw_ip_denied_session_start();

$collected = array(
'ipv4' => array(),
'ipv6' => array(),
);

if ( isset( $_SESSION['mw_ip_denied_collected'] ) && is_array( $_SESSION['mw_ip_denied_collected'] ) ) {
$prev = $_SESSION['mw_ip_denied_collected'];
if ( isset( $prev['ipv4'] ) && is_array( $prev['ipv4'] ) ) {
$collected['ipv4'] = array_values( array_unique( $prev['ipv4'] ) );
}
if ( isset( $prev['ipv6'] ) && is_array( $prev['ipv6'] ) ) {
$collected['ipv6'] = array_values( array_unique( $prev['ipv6'] ) );
}
}

mw_ip_denied_collect_server_ips( $collected );
mw_ip_denied_collect_client_post( $collected );

// サーバーサイドでの外部API取得は削除 (クライアントIPではなくサーバーIPが取れてしまうため)

$collected['ipv4'] = array_values( array_unique( $collected['ipv4'] ) );
$collected['ipv6'] = array_values( array_unique( $collected['ipv6'] ) );
$_SESSION['mw_ip_denied_collected'] = $collected;

return $collected;
}
}
