<?php
/**
 * Plugin Name: MW IP Denied
 * Plugin URI: http://2inc.org
 * Description: MW IP Denied allows you to set access restrictions by IP address for each article. When access is restricted and there is template-access-denied.php, MW IP Denied load it.
 * Version: 0.3.2
 * Author: Takashi Kitajima
 * Author URI: http://2inc.org
 * Text Domain: mw-ip-denied
 * Domain Path: /languages/
 * Created: february 5, 2013
 * Modified: December 6, 2013
 * License: GPL2
 *
 * Copyright 2013 Takashi Kitajima (email : inc@2inc.org)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
class MW_IP_Denied {

	const NAME = 'mw-ip-denied';
	const DOMAIN = 'mw-ip-denied';

	/**
	 * __construct
	 * 初期化等
	 */
	public function __construct() {
		load_plugin_textdomain( self::DOMAIN, false, basename( dirname( __FILE__ ) ) . '/languages' );
		// 有効化した時の処理
		register_activation_hook( __FILE__, array( __CLASS__, 'activation' ) );
		// アンインストールした時の処理
		register_uninstall_hook( __FILE__, array( __CLASS__, 'uninstall' ) );

		// 記事公開時にメール送信
		add_action( 'save_post', array( $this, 'save_post' ) );
		// メタボックスの追加
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		// アクセス制限がかかっているか判定
		add_action( 'wp', array( $this, 'check_ip_access_allow' ) );
		// ショートコード
		add_shortcode( 'mw-ip-allow', array( $this, 'shortcode_ip_allow' ) );
		add_shortcode( 'mw-ip-deny', array( $this, 'shortcode_ip_deny' ) );
	}

	/**
	 * activation
	 * 有効化した時の処理
	 */
	public static function activation() {
	}

	/**
	 * uninstall
	 * アンインストールした時の処理
	 */
	public static function uninstall() {
		delete_post_meta_by_key( self::NAME );
	}

	/**
	 * save_post
	 * 許可するIPアドレスを保存
	 * @param	$post_ID
	 */
	public function save_post( $post_ID ) {
		if ( ! isset( $_POST[self::NAME.'_nonce'] ) )
			return $post_ID;
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE )
			return $post_ID;
		if ( !wp_verify_nonce( $_POST[self::NAME.'_nonce'], self::NAME ) )
			return $post_ID;
		if ( !current_user_can( 'manage_options', $post_ID ) )
			return $post_ID;

		$ips = $_POST[self::NAME.'_ips'];
		$ips = trim( $ips );
		$ips = str_replace( array( "\r\n", "\r", "\n" ), '', $ips );
		if ( empty( $ips ) ) {
			delete_post_meta( $post_ID, self::NAME );
		} else {
			update_post_meta( $post_ID, self::NAME, $ips );
		}
	}

	/**
	 * admin_menu
	 * 設定メニューにプラグインのサブメニューを追加する
	 */
	public function admin_menu() {
		$post_types = get_post_types( array( 'public' => true ) );
		unset( $post_types['attachment'] );
		unset( $post_types['links'] );
		foreach ( $post_types as $post_type ) {
			add_meta_box( self::NAME, __( 'Allowd IP', self::DOMAIN ), array( $this, 'add_meta_box' ), $post_type, 'side' );
		}
	}

	/**
	 * add_meta_box
	 * 許可するIPを入力するメタボックスを出力
	 */
	public function add_meta_box() {
		global $post;
		?>
		<input type="hidden" name="<?php echo esc_attr( self::NAME ); ?>_nonce" value="<?php echo wp_create_nonce( self::NAME ); ?>" />
		<textarea name="<?php echo esc_attr( self::NAME ); ?>_ips" cols="30" rows="3"><?php echo esc_attr( get_post_meta( $post->ID, self::NAME, true ) ); ?></textarea>
		<p class="howto">
			<?php _e( 'Please write the comma-separated IP address that you want to allow.  you can use subnet mask. If you leave this blank to allow all access.', self::DOMAIN ); ?>
		</p>
		<?php
	}

	/**
	 * check_ip_access_allow
	 * アクセス制限がかかっているか判定
	 */
	public function check_ip_access_allow() {
		global $post;
		if ( ! isset( $post->ID ) )
			return;
		$ips = get_post_meta( $post->ID, self::NAME, true );
		if ( empty( $ips ) )
			return;

		$_ret = $this->_check_ip_access_allow( $ips );
		if ( ! $_ret )
			add_action( 'template_redirect', array( $this, 'load_denied_template' ) );
	}

	/**
	 * _check_ip_access_allow
	 * アクセス制限がかかっているか判定
	 * @param	$ips
	 * @return	Boolean
	 */
	protected function _check_ip_access_allow( $ips ) {
		$remoteIp = $_SERVER['REMOTE_ADDR'];
		$allowIps = explode( ',', $ips );

		foreach ( $allowIps as $allowIp ){
			$allowIp = trim( $allowIp );
			if ( preg_match( '/\/\d+$/', $allowIp ) ) {
				list( $ip, $mask ) = explode( '/', $allowIp);
				$remoteLong = ip2long( $remoteIp ) >> ( 32 - $mask );
				$allowLong = ip2long( $ip ) >> ( 32 - $mask );
			} else {
				$remoteLong = ip2long( $remoteIp );
				$allowLong = ip2long( $allowIp );
			}

			// アクセス元IPの形式が不正
			if ( $remoteLong === false || $remoteLong === -1 )
				continue;
			// 許可IPの形式が不正
			if ( $allowLong === false || $allowLong === -1 )
				continue;
			// アクセス元IPが許可IPに含まれる
			if ( $remoteLong == $allowLong ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * load_denied_template
	 * アクセス制限時の処理。template-access-denied.phpがある場合はそれを読み込む。
	 */
	public function load_denied_template() {
		header( 'HTTP/1.1 401 Access Denied' );
		if ( locate_template( array( 'template-access-denied.php' ), false ) ) {
			get_template_part( 'template-access-denied' );
		} else {
			echo '<h1>Access Denied</h1>';
			exit;
		}
	}

	/**
	 * shortcode_ip_allow
	 * @param	$atts
	 * @param	$content
	 * @return	$content
	 */
	public function shortcode_ip_allow( $atts, $content = null ) {
		$atts = shortcode_atts( array(
			'allow' => '',
		), $atts );

		$ips = $atts['allow'];
		if ( empty( $ips ) )
			return do_shortcode( $content );

		$_ret = $this->_check_ip_access_allow( $ips );
		if ( $_ret )
			return do_shortcode( $content );
	}

	/**
	 * shortcode_ip_deny
	 * @param	$atts
	 * @param	$content
	 * @return	$content
	 */
	public function shortcode_ip_deny( $atts, $content = null ) {
		$atts = shortcode_atts( array(
			'deny' => '',
		), $atts );

		$ips = $atts['deny'];
		if ( empty( $ips ) )
			return do_shortcode( $content );

		$_ret = $this->_check_ip_access_allow( $ips );
		if ( ! $_ret )
			return do_shortcode( $content );
	}
}

// オブジェクト化（プラグイン実行）
$MW_IP_Denied = new MW_IP_Denied();
