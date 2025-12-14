=== MW IP Denied ===
Contributors: inc2734(0.3.2), hiro-gj(2025.12.14:0.4.0)
Tags: ip, deny, denied, access
Requires at least: 3.3
Tested up to: 3.5
Stable tag: 0.4.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

MW IP Denied allows you to set access restrictions by IP address for each article.

== Description ==

MW IP Denied allows you to set access restrictions by IP address for each article. When access is restricted and there is template-access-denied.php, MW IP Denied load it.

You can also use short code for controlling the access on a part of the article.

Only the IP address that you specify can access.
[mw-ip-allow allow="IPAddress,…"]text[/mw-ip-allow]

Only the IP address that you specify can not access.
[mw-ip-deny deny="IPAddress,…"]text[/mw-ip-deny]

== Installation ==

1. Upload `mw-ip-denied` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress

== Changelog ==

= 0.4.0 =
* Supported IPv6 address.
* (for Debug)Added display of remote IP address on access denied screen.

= 0.3.2 =
* Fix add meta box bug.

= 0.3.1 =
* Bug fix.

= 0.3 =
* First Commit.
