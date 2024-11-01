=== VigilanTor ===
Contributors: drew010
Donate link: https://drew-phillips.com/donate
Tags: tor, tor blocker, comments, spam, proxy, security, block, registration, captcha
Requires at least: 4.0
Requires PHP: 5.6
Tested up to: 6.3.2
Stable tag: 1.3.12
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl.txt

Add a layer of security to your WordPress site with the ability to block Tor users from commenting, registering, logging in and more.

== Description ==

[Tor](https://www.torproject.org/ "Tor") is an invaluable tool for protecting free-speech, privacy, and preventing surveillance but when abused it can protect the identity of malicious users and make tracking their activities more difficult.  "Hackers" might use Tor to run security scans on your website or spam websites with comments and fake registrations.

The purpose of this plugin is to give you the power to block certain Tor activity from your WordPress site.

Features include:

* Block Tor users from registering on your site
* Allow Tor registrations, but flag them for review
* Block logins from Tor (useful for preventing brute force attacks and securing your admin panel)
* Block Tor users from posting comments to your site
* Block spammy pingbacks & trackbacks from Tor IP addresses
* Block Tor users from your entire WordPress site
* Permit access after solving a CAPTCHA (requires hCaptcha for WordPress plugin)
* Real-time blocking using the Tor DNS exit list service
* Near real time blocking using a cached blocklist which can be updated every 10 minutes or more
* Custom blocklist support.  Block IP addresses or host networks.
* Statistics to show how many Tor actions have been blocked by this plugin

This plugin is compatible with BuddyPress, the popular Login With Ajax plugin, and hCaptcha.

If there is a feature missing that you would like, request it!

If you opt to use the real-time blocking, each IP address looked up is cached for 5 minutes for efficiency.

The Tor IP lists that are downloaded only contain "exit node" IP addresses so it is relatively small and the list is searched using a binary search so the plugin is very fast!

This plugin also adds two shortcodes which can be used to display specific content to Tor or non-Tor users. Shortcode usage:

    [tor_users]Hi, I see you're using Tor.  I support privacy and free-speech too! Visitors not using Tor will not see this message.[/tor_users]
    [non_tor_users]Defend yourself against tracking and surveillance. Circumvent censorship. Visit torproject.org to learn more. Visitors already using Tor will not see this message.[/non_tor_users]

**Support Tor**

Tor is a great thing.  If you agree, consider [volunteering](https://www.torproject.org/getinvolved/volunteer.html.en), [donating](https://www.torproject.org/donate/donate.html.en) to the Tor project, or expand the Tor network by [sponsoring a Tor relay](https://drew-phillips.com/tor-nodes/) which will be maintained by the plugin author.

**Support this plugin**

The author of this plugin values Tor as well as the security of your website.  Considerable effort went into the development of this plugin as well as the code and infrastructure that provides you with the up-to-date exit lists.

You can support this plugin by installing it, rating it positively, [donating](https://drew-phillips.com/donate/ "Donating") to the author, or [sponsoring a Tor relay](https://drew-phillips.com/tor-nodes/) which will be operated by the plugin developer in your honor.


== Installation ==

Installation is simple

1. Download the plugin and extract contents to a folder named `vigilantor` in your `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Customize the settings from your WordPress administration panel

Or, from the WordPress admin screen:

1. Navigate to `Plugins` >> `Add new`
2. Search for `VigilanTor` and click `Install Now`!

== Frequently Asked Questions ==

= How does this plugin work? =

This plugin detects Tor users by using a pre-downloaded list of Tor IP addresses.  One nice thing about the Tor network is that it is very easy to get lists of IP addresses that allow Tor users to access the internet.

When a user visits your site and tries to perform one of the restricted actions, their IP is checked against the list of known Tor exit IP addresses.  If it's a match, they won't be allowed to do what they were trying to do.

= Where do the exit lists come from? =

Exit lists are served from these domains:

* www2.openinternet.io
* openinternet.io

One of these lists is maintained by us.  You can see the contents [here](https://www2.openinternet.io/tor/tor-exit-list.txt "here").  Please be kind if you choose to use it for purposes other than this plugin.

= How often are the exit lists updated? =

You can choose to update the exit lists every 10, 20, 30, 60, 120, or 360 minutes. Updating every 30 or 60 minutes is recommended.

= How does the real time checking work? =

The real-time checking is very fast since it uses the public [Tor DNS exit list service](https://www.torproject.org/projects/tordnsel.html.en) run by the Tor project.  A small DNS request is sent that contains the visitor's IP address which is compared to a list of observed exit relays.

The DNS request will yield a positive response from the service if the criteria matches.  Since DNS uses UDP and the packets are small, this is typically a fast and efficient way to perform the check.

= How does the CAPTCHA protection work? =

In order to use the optional CAPTCHA protection, first install the "hCaptcha for Wordpress" plugin and enable the "Block Tor users from all of WordPress" configuration option in VigilanTor.

When a Tor user visits your site, they will be presented with a CAPTCHA challenge.  After correctly solving the CAPTCHA, a session cookie will be set in the browser containing a secret token (stored in the WP database) that bypasses the Tor blocking.  The cookie is saved in the database for 1 hour, and it's value is changed on each visit to prevent the cookie from being used by multiple browsers.

= What PHP version does VigilanTor require? =

VigilanTor should work with PHP 5.6 or greater. It has been tested on PHP 5.6, 7.0 - 7.4, and 8.0. If you run into any problems, please [report them here](https://wordpress.org/support/plugin/vigilantor). This plugin is *not* compatible with any PHP 4 version!

== Screenshots ==

1. VigilanTor settings menu in WordPress admin screen
2. Flagged users who registered using Tor (compatible with BuddyPress)
3. Message shown when Tor users are blocked from logging in
4. Blocked login integrating with Ajax login plugins
5. Message shown when Tor users attempt to register (compatible with BuddyPress)
6. Blocking a comment from a Tor user
7. Total site block showing generic message to Tor users
8. Total site block showing a custom page to Tor users (works with most themes)
9. CAPTCHA protection for total site block when no block page is specified
10. CAPTCHA protection added to the block page

== Changelog ==

= 1.3.12 =
* Update plugin compatibility to WordPress 6.3.2

= 1.3.11 =
* Update plugin compatibility to WordPress 6.2
* Update to work with hCaptcha 2.x and 1.x
* Sanitize vitor_realtime_timeout option in admin settings page

= 1.3.10 =
* Update plugin compatibility to WordPress 5.9
* Update readme with hCaptcha info

= 1.3.9 =
* Update plugin compatibility to WordPress 5.6
* Tor's bulk exit list is now integrated in blocklist; separate download no longer necessary
* Fix hCaptcha integration to work with latest hCaptcha version
* Ensure plugin compatibility with PHP 8.0

= 1.3.8 =
* Fix change that broke compatibility with PHP < 5.6

= 1.3.7 =
* Add support for hCaptcha on block page (see hCaptcha.com & wordpress.org/plugins/hcaptcha-for-forms-and-more/)
* Add option to enable Cloudflare support (recognize CF-Connecting-IP header)
* Fallback to other page templates when the current theme doesn't have a "Page" template

= 1.3.6 =
* Update real-time lookup to use newer, simplified Tor DNSEL service (see https://blog.torproject.org/changes-tor-exit-list-service)
* Exit lists are now a combination of the Tor Project's bulk exit list and our own maintained Tor exit list
* Add `non_tor_users` shortcode
* Update compatibility to WordPress 5.4.1

= 1.3.5 =
* No changes, released immediately after 1.3.4 where the update URLs were left commented out

= 1.3.4 =
* Update compatibility to WordPress 5.2.3
* Add backup update URL
* Fix issue with Ajax list update for when wp-cron is broken; may have used URL with WP_Http that resulted in a redirect and was not followed

= 1.3.3 =
* Add option to use a custom message when "Block Tor users from all of WordPress" is enabled
* When blocking from the entire site and not using custom block page, set page title to "Access Denied" instead of the default "Wordpress Error"

= 1.3.2 =
* Add custom blocklist support
* Add option to hide comment form from blocked users
* Reduce download size of exit list and include all IPs from Tor network
* Add text domain to plugin so it can be translated

= 1.3.1 =
* Expand Tor IP list from relays with the Exit flag to all nodes (some relays without Exit flag in directory are providing exit services)

= 1.3 =
* Add optional CAPTCHA protection for Tor addresses
* Improve exit list update process when wp-cron isn't working properly

= 1.2 =
* Add blocking statistics tracking
* Prevent race condition causing the exit list to download twice in a short time
* Remove some PHP 5.3 syntax to lower PHP version requirement

= 1.1 =
* Fix issue with Total Site Block option returning false positive

= 1.0 =
* Initial release!

== Upgrade Notice ==

= 1.0 =
* None!
