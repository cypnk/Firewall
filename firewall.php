<?php
/**
 *  Firewall is a companion project intended to function as a barrier to
 *  abusive requests and malicious bots.
 *  
 *  Firewall runs before any other application code and it requries only
 *  a single write-enabled directory to function.
 *  
 *  Set the SKIP_LOCAL constant to be defined in your code to prevent 
 *  this file from being called on its own. Firewall will keep track of 
 *  your traffic in the firewall.db file set below.
 *  
 *  A lot of this was inspired by the Bad Behavior package but does not
 *  use the same code.
 *  
 *  @link http://bad-behavior.ioerror.us
 */

// Your custom denied message
define( 'KILL_MSG', <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Denied</title>
</head>
<body>
	<p>Access to this resource is restricted</p>
</body>
</html>
HTML
);

// Location of your database file (based on relative path)
// This will be where Firewall creates a SQLite database
define( 'FIREWALL_DB', 
	\realpath( \dirname( __FILE__ ) ) . '/data/firewall.db' );

// Use this instead if your code is outside the web root directory
// define( 'FIREWALL_DB',
//	\realpath( \dirname( __FILE__, 2 ) ) . '/data/firewall.db' );


/**********************
 *  Configuration end
 **********************/


if ( !defined( 'DATA_TIMEOUT' ) ) {
	define( 'DATA_TIMEOUT', 10 );
}


if ( !defined( 'SKIP_LOCAL' ) ) {
	fw_instaKill();
}

// Each command is separated by a -- -- string
define( 'FIREWALL_DB_PREP', <<<SQL
CREATE TABLE firewall (
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
	ip TEXT NOT NULL, 
	ua TEXT NOT NULL, 
	uri TEXT NOT NULL, 
	method TEXT NOT NULL, 
	headers TEXT NOT NULL, 
	expires DATETIME DEFAULT NULL,
	created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);-- --
CREATE INDEX idx_firewall_on_ip ON firewall ( ip ASC );-- --
CREATE INDEX idx_firewall_on_ua ON firewall ( ua ASC );-- --
CREATE INDEX idx_firewall_on_uri ON firewall ( uri ASC );-- --
CREATE INDEX idx_firewall_on_method ON firewall ( method ASC );-- --
CREATE INDEX idx_firewall_on_expires ON firewall ( expires DESC );-- --
CREATE INDEX idx_firewall_on_created ON firewall ( created ASC );-- --
CREATE TRIGGER firewall_insert AFTER INSERT ON firewall FOR EACH ROW 
BEGIN
	UPDATE firewall SET 
		expires = datetime( 
			( strftime( '%s','now' ) + 604800 ), 
			'unixepoch'
		) WHERE rowid = NEW.rowid;
	
	DELETE FROM firewall WHERE 
		strftime( '%s', expires ) < 
		strftime( '%s', created );
END;
SQL
);

define( 'FIREWALL_DB_INSERT', <<<SQL
INSERT INTO firewall ( ip, ua, uri, method, headers ) 
	VALUES ( :ip, :ua, :uri, :method, :headers );
SQL
);

function fw_getDb( bool $close = false ) {
	static $db;
	if ( isset( $db ) ) {
		if ( $close ) {
			$db = null;
			return;
		}
		return $db;
	}
	try {
		// Connection options
		$opts	= [
			\PDO::ATTR_TIMEOUT		=> \DATA_TIMEOUT,
			\PDO::ATTR_DEFAULT_FETCH_MODE	=> \PDO::FETCH_ASSOC,
			\PDO::ATTR_PERSISTENT		=> false,
			\PDO::ATTR_EMULATE_PREPARES	=> false,
			\PDO::ATTR_ERRMODE		=> 
				\PDO::ERRMODE_EXCEPTION
		];
		
		$first_run = false;
		if ( !\file_exists( \FIREWALL_DB ) ) {
			$first_run = true;
		}
		
		$db	= 
		new \PDO( 'sqlite:' . \FIREWALL_DB, null, null, $opts );
		
		// New database? Create tables and presets
		if ( $first_run ) {
			$db->exec( 'PRAGMA encoding = "UTF-8";' );
			$db->exec( 'PRAGMA page_size = "16384";' );
			$db->exec( 'PRAGMA auto_vacuum = "2";' );
			$db->exec( 'PRAGMA temp_store = "2";' );
			$db->exec( 'PRAGMA secure_delete = "1"' );
			
			// Run create
			$sql	= \explode( '-- --', \FIREWALL_DB_PREP );
			foreach( $sql as $q ) {
				if ( empty( trim( $q ) ) ) {
					continue;
				}
				$db->exec( $q );
			}	
		}
		
		$db->exec( 'PRAGMA journal_mode = WAL;' );
		return $db;
		
	} catch ( \PDOException $e ) {
		die( 'Error creating firewall database. Check if you have write permissions to the data folder' );
	}
	return $db;
}

// End response immediately
function fw_instaKill() {
	\http_response_code( 403 );
	die( KILL_MSG );
}

// String contains a fragment
function fw_has( $source, $term ) {
	return 
	( empty( $source ) || empty( $term ) ) ? 
		false : ( false !== \strpos( $source, $term ) );
}

// String starts with
function fw_startsWith( $find, $collection ) {
	foreach ( $collection as $c ) {
		if ( 0 === \strncasecmp( $find, $c, \strlen( $c ) ) ) {
			return true;
		}
	}
	return false;
}

// Search string for a fragment in an array
function fw_needleSearch( $find, $collection ) {
	foreach ( $collection as $c ) {
		if ( fw_has( $find, $c ) ) {
			return true;
		}
	}
	
	return false;
}

// IP v4 address in given subnet
function fw_inIPv4Range( $ip, $subnet ) {
	// Set default subnet to 32
	if ( !fw_has( $subnet, '/' ) ) {
		$subnet .= '/32';
	}
	
	list( $range, $mask ) = \explode( '/', $subnet, 2 );
	$ndec = -1 << ( 32 - $mask );
	
	return 
	( \ip2long( $ip ) & $ndec ) === ( \ip2long( $range ) & $ndec );
}

// Convert IPv6 mask to byte array for easier matching
function fw_IPv6Array( $net ) {
	$ip	= \str_repeat( 'f', $net / 4 );
	switch( $net % 4 ) {
		case 1:
			$ip .= '8';
			break;
		case 2:
			$ip .= 'c';
			break;
			
		case 3:
			$ip .= 'e';
			break;
	}
	// Fill out mask
	return \pack( 'H*', \str_pad( $ip, 32, '0' ) );
}

// IP v6 address in given subnet
function fw_inIPv6Range( $ip, $subnet ) {
	// Set default subnet to 64
	if ( !fw_has( $subnet, '/' ) ) {
		$subnet .= '/64';
	}
	
	list( $range, $mask ) = \explode( '/', $subnet, 2 );
	$sbit	= \inet_pton( $ip );
	
	return 
	( $sbit & fw_IPv6Array( $mask ) ) == \inet_pton( $range );
}

// IP Address in given range collection
function fw_inSubnet( $ip, $subnet ) {
	
	// If this is an IPv6 address
	if ( \filter_var( 
		$ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6 
	) ) {
		foreach ( $subnet as $net ) {
			// Skip searching IPv4 addresses
			if ( !fw_has( $net, ':' ) ) {
				continue;
			}
			if ( fw_inIPv6Range( $ip, $net ) ) {
				return true;
			}
		}
		
	// This is an IPv4 address
	} else {
		foreach ( $subnet as $net ) {
			// Skip searching IPv6 addresses
			if ( fw_has( $net, ':' ) ) {
				continue;
			}
			
			if ( fw_inIPv4Range( $ip, $net ) ) {
				return true;
			}
		}
	}
	
	return false;
}

// Browser User Agent
function fw_getUA() {
	static $ua;
	
	if ( isset( $ua ) ) {
		return $ua;
	}
	$ua	= trim( $_SERVER['HTTP_USER_AGENT'] ?? '' );
	return $ua;
}

// Current querystring, if present
function fw_getQS() {
	static $qs;
	if ( isset( $qs ) ) {
		return $qs;
	}
	$qs	= $_SERVER['QUERY_STRING'] ?? '';
	return $qs;
}

// Best effort IP address
function fw_getIP() {
	static $ip;
	
	if ( isset( $ip ) ) {
		return $ip;
	}
		
	$ip	= $_SERVER['REMOTE_ADDR'];
	$va	= 
	( SKIP_LOCAL ) ?
		\filter_var( $ip, \FILTER_VALIDATE_IP ) : 
		\filter_var(
			$ip, 
			\FILTER_VALIDATE_IP, 
			\FILTER_FLAG_NO_PRIV_RANGE | 
			\FILTER_FLAG_NO_RES_RANGE
		);
	
	$ip	= ( false === $va ) ? '' : $ip;
	return $ip;	
}

function fw_uaCheck() {
	$ua	= fw_getUA();
	
	// User Agent contains non-ASCII characters?
	if ( !\mb_check_encoding( $ua, 'ASCII' ) ) {
		return true;
	}
	
	// Starting flags
	static $ua_start = [
		' ',
		'\"',
		'-',
		';',
		'%',
		'$',
		'<?',
		'(',
		'Android', 
		'iTunes',
		'U;',
		'Korvo',
		'MSIE',
		'user'
	];
	
	if ( fw_startsWith( $ua, $ua_start ) ) {
		return true;
	}
	
	// Suspicious user agent fragments
	static $ua_frags = [
		// Injection in the UA
		'<?php',
		'IDATH.c\<?',
		'<?=`$_',
		'IDATH.c??<script',
		'IDATHKc??<script',
		
		// There's no space in front of ;
		' ; MSIE',
		
		// Invalid tokens
		'~~',
		'**',
		'...',
		'\\\\',
		
		// Doesn't exist
		'.NET CLR 1)',
		'.NET CLR1',
		'.NET_CLR',
		'.NET-CLR',
		
		'\r',
		'<sc',
		'(Chrome)',
		'Widows',
		'360Spider',
		'8484 Boston Project',
		
		// There shouldn't be HTML in user agent strings
		'a href=',
		
		'Aboundex',
		'Acunetix',
		'adwords',
		'Alexibot',
		'AIBOT',
		
		// Misspelled "Android"
		'Andriod',
		'Andreod',
		'Andirod',
		'Angroid',
		
		// Forged Android
		'Android --',
		'Android 2.x',
		
		'AntivirXP08',
		'AOLBuild /',
		
		// Misspelled "Apple"
		'Appel',
		'Appl ',
		'Aplle',
		
		'asterias',
		'Atomic',
		'attach',
		'atSpider',
		'autoemail',
		'AWI ',
		'BackDoor',
		'BackWeb',
		'BadBehavior',
		'Bad Behavior',
		
		// Fake Baidu
		'baidu /',
		'baidu/ ',
		'bai du/',
		'baiduspider/ ',
		'baiduspider /',
		'baidu spider',
		'baiduspider/1.',
		
		'Bandit',
		'BatchFTP',
		'Bigfoot',
		
		// Fake Bingbot
		'bingbot /',
		'bingbot/ ',
		'bing bot/',
		
		'Black.Hole',
		'BlackHole',
		'BlackWidow',
		'blogsearchbot-martin',
		'BlowFish',
		'Bot mailto:craftbot@yahoo.com',
		'BotALot',
		'BrowserEmulator',
		'Buddy',
		'BUILDDATE',
		'BuiltBotTough',
		'Bullseye',
		'BunnySlippers',
		'bwh3',
		'CAIME0',
		'CAIMEO',
		'Cegbfeieh',
		'centurybot',
		'changedetection',
		'CheeseBot',
		'CherryPicker',
		'China Local Browse',
		'ChinaClaw',
		'Clarity',
		'Clearswift',
		'clipping',
		'Cogentbot',
		'Collector',
		'ContactBot',
		'ContactSmartz',
		'ContentSmartz',
		
		// Fake compatibility
		'compatible ;',
		'compatible-',
		
		'Cool ',
		'cognitiveseo',
		'CoralWebPrx',
		'core-project',
		'Copier',
		'CopyRightCheck',
		'cosmos',
		'Crescent',
		'Cryptoapi',
		'Custo',
		'DataCha0s',
		'DBrowse',
		'Demo Bot',
		'Diamond',
		'Digger',
		'DIIbot',
		'DISCo',
		'DittoSpyder',
		'discovery',
		'DnyzBot',
		'Download',
		'dragonfly',
		'Drip',
		'DSurf',
		'DTS Agent',
		'eCatch',
		'Easy',
		'EBrowse',
		'ecollector',
		'Educate Search',
		'Email',
		'Emulator',
		'Enchanc',
		'EroCrawler',
		'Exabot',
		'Express WebPictures',
		
		// Extractors
		'Extrac',
		
		'evc-batch',
		'EyeNetIE',
		
		// Fake Facebook bot
		'Facebot Twitterbot',
		'facebookexternal/',
		'facebookexternal /',
		'facebookexternalhit/ ',
		'facebookexternalhit /',
		
		'Fail',
		'Fatal',
		'FlashGet',
		'FHscan',
		
		// Too old to be viable
		'Firebird',
		'Firefox/40',
		
		'flunky',
		'Franklin Locator',
		'Foobot',
		'Forum Poster',
		'FrontPage',
		'FSurf',
		'Full Web Bot',
		'FunWeb',
		'Gecko/2525',
		'Generic',
		'GetRight',
		'GetWeb!',
		'Ghost',
		'Gluten Free Crawler',
		'Go!Zilla',
		'Go-Ahead-Got-It',
		'Go-http-client',
		'gotit',
		
		// Fake Googlebot
		'googlebot /',
		'googlebot/ ',
		'googlebot/1.',
		'Googlebot Image',
		'Googlebot-Image/ ',
		'Googlebot-Image /',
		'Googlebot Video',
		'Googlebot-Video/ ',
		'Googlebot-Video /',
		'Mediapartners Google',
		
		'Gowikibot',
		'Grab',
		'Grafula',
		'GrapeshotCrawler',
		'grub',
		'hanzoweb',
		'Harvest',
		'Havij',
		'hloader',
		'HMView',
		'HttpProxy',
		
		// Resource-hungry archiver (comment to make exception)
		'HTTrack',
		
		'human',
		'hverify',
		
		// Amazon Alexa
		'ia_archiver',
		
		'IlseBot',
		'IndeedBot',
		'Indy Library',
		'InfoNaviRobot',
		'InfoPath',
		'InfoTekies',
		'informant',
		'Insuran',
		'Intelliseek',
		'InterGET',
		
		// *Not* IE. UA is likely a bot
		'Internet Explorer',
		
		// Misspelled "Intel"
		'Intle',
		'Itele',
		'Intle',
		
		'Intraformant',
		
		// Fake iPhone
		'iPhone/',
		'iPhone /',
		'iPhoneOS',
		'iPhone OS/',
		
		'ISC Systems iRc',
		'Iria',
		'Java 1.',
		'Java/1',
		'Jakarta',
		'Jenny',
		'JetCar',
		'JOC',
		'JustView',
		'Jyxobot',
		'Kenjin',
		'Keyword',
		'larbin',
		'Leacher',
		'LexiBot',
		'LeechFTP',
		'libwhisker',
		'libwww-perl',
		'lftp',
		'libWeb/clsHTTP',
		'likse',
		'LinkScan',
		'Lightning',
		'linkdexbot',
		'LNSpiderguy',
		'LinkWalker',
		'Lobster',
		'Locator',
		'LWP',
		
		// Misspelled "Macintosh"
		'Macnitosh',
		'Macinotsh',
		'Mackintosh',
		'Macintohs',
		'Mcintosh',
		
		'Magnet',
		'Mag-Net',
		'MarkWatch',
		'Mata.Hari',
		
		// Automated tool (can be abused)
		'Mechanize',
		
		'Memo',
		'Meterpreter/Windows',
		'Microsoft URL',
		'Microsoft.URL',
		'MIDown',
		'Ming Mong',
		'Missigua',
		'Mister',
		'MJ12bot/v1.0.8',
		'moget',
		'Mole',
		'Morfeus',
		
		// Not the blog engine
		'Movable Type',
		
		// Fake Mozilla
		'Mozilla.*NEWT',
		'Mozilla/0',
		'Mozilla/1',
		'Mozilla/2',
		'Mozilla/3',
		'Mozilla/4.0(',
		'Mozilla/4.0+(compatible;+',
		'Mozilla/4.0 (Hydra)',
		'Mozilla /',
		'Mozilla/9.0',
		
		// Fake MSNBot
		'msnbot /',
		'MS Search 6.0 Robot',
		
		'MSIE 7.0 ; Windows NT',
		'MSIE 7.0; Windows NT 5.2',
		'MSIE 7.0;  Windows NT 5.2',
		
		'Murzillo',
		'MVAClient',
		'MyApp',
		'MyFamily',
		'Navroad',
		'NearSite',
		'NetAnts',
		'NetMechanic',
		'Netsparker',
		'NetSpider',
		'Net Vampire',
		'NetZIP',
		'Nessus',
		'NG',
		'NICErsPRO',
		'Nikto',
		'Ninja',
		'Nimble',
		'Nmap',
		'NPbot',
		'Nomad',
		'Nutch',
		'Nutscrape',
		'NextGen',
		'Octopus',
		'OmniExplorer',
		'Opera/9.64(',
		
		// Offline anything is a scraper
		'Offline',
		
		'Openfind',
		'OutfoxBot',
		'panscient',
		'Papa Foto',
		'PaperLiBot',
		'Parser',
		'pavuk',
		'pcBrowser',
		'PECL::',
		'PeoplePal',
		'Perman Surfer',
		'PHP',
		'Pockey',
		'PMAFind',
		'POE-Component',
		'PowerMapper',
		'ProPowerBot',
		'proximic',
		'psbot',
		'psycheclone',
		'Pump',
		'PussyCat',
		'PycURL',
		'Python-urllib',
		'qiqi',
		'QueryN',
		'raventools',
		'RealDownload',
		'Reaper',
		'Recorder',
		'ReGet',
		'RepoMonkey',
		'Research',
		'RMA',
		'revolt',
		'RukiCrawler',
		
		// Revisions are always numbers, not x
		'rv:x.',
		
		// Misconfigured bot
		'rv:geckoversion',
		
		// Scraper
		'Scrapy',
		
		'Shockwave Flash',
		'SemrushBot',
		'sentiment',
		'SeoBotM6',
		'seocharger',
		'SEOkicks-Robot',
		'Siphon',
		'SiteSnagger',
		'SlySearch',
		'SmartDownload',
		'SMTBot',
		'Snake',
		'Snapbot',
		'sogou',
		'SpaceBison',
		'Spank',
		'spanner',
		'sqlmap',
		'Sqworm',
		'Stress',
		'Stripper',
		'Strateg',
		'strange',
		'study',
		'Sucker',
		'SuperBot',
		'SuperCleaner',
		'Super Happy Fun',
		'SuperHTTP',
		'Surfbot',
		'suzuran',
		'Synapse',
		'Szukacz',
		'taboola',
		'tAkeOut',
		'Test',
		'TightTwatBot',
		'Titan',
		'Teleport',
		'Telesoft',
		'TO-Browser/TOB',
		
		// No space before ;
		'Touch ;',
		
		'TrackBack',
		'trandoshan',
		'Trellian',
		
		// Misspelled "Trident"
		'Tridet',
		'Tridnet',
		'Tridnet /',
		'Trident /',
		
		'True_Robot',
		'Turing Machine',
		'turingos',
		'TurnitinBot',
		'like TwitterBot',
		'Tweetmeme',
		'Ultraseek',
		'Unknown',
		'Ubuntu/9.25',
		'unspecified',
		'user',
		
		// Strange formatting of the two words
		'User Agent:',
		'User-Agent:',
		
		// Fake emulator
		'Version/ ',
		'Version /',
		
		'VoidEYE',
		'w3af',
		'Warning',
		'Web Image Collector',
		'WebaltBot',
		'WebAuto',
		'WebFetch',
		'WebGo',
		
		// Misspelled "WebKit" a la "AppleWebKit"
		' Web Kit',
		' Webkit',
		'Web Kit',
		'Webit',
		'WebiKit',
		'Webikt',
		'Webkit /',
		
		'WebmasterWorldForumBot',
		'WebSauger',
		'WebSite-X Suite',
		'Website eXtractor',
		'Website Quester',
		'Webster',
		'WebWhacker',
		'WebZIP',
		'WeSEE',
		'Whacker',
		'Widow',
		'Winnie Poh',
		
		// These are (very) old. Likely bots
		'Win95',
		'Win98',
		'WinME',
		'Win 9x 4.90',
		'Windows 3',
		'Windows 95',
		'Windows 98',
		
		'Windows NT 4',
		'Windows NT;',
		'Windows NT 5.0;)',
		'Windows NT 5.1;)',
		'Windows NT 9.',
		'Windows XP 5',
		
		'WinHttp',
		
		'WISEbot',
		'WISENutbot',
		
		//  Vulnerability scanner or trackback
		'Wordpress',
		
		'WWWOFFLE',
		'Vacuum',
		'VCI',
		'Xedant',
		'Xaldon',
		'Xenu',
		'XoviBot',
		
		// Fake Yahoo! bot
		'Yahoo !',
		'Slurb;',
		'Slurb ;',
		'Slurp ;',
		'Search Monkey',
		'/ ysearch',
		'/y search',
		
		'Zeus',
		'ZmEu',
		'ZoomBot',
		'Zyborg'
	];
	
	return fw_needleSearch( $ua, $ua_frags );
}

function fw_uriCheck() {
	static $uri_frags	= [
		// Database NULL
		'0x31303235343830303536',
		
		// Directory traversal
		'../',
		'..\\',
		'..%2F',
		'..%u2216',
		
		// Attempt to reveal PHP version
		'?=PHP',
		
		// DB scan
		'%60information_schema%60',
		'DECLARE%20@',
		'~',
		
		// Shouldn't see fragments in the URI sent to the server
		'#',
		
		// Potential vulnerability scan
		'.git/',
		'%7e',
		'<?=`$_',
		'<?php',
		'<script',
		'%3cscript%20',
		'%27%3b%20',
		'%22http%3a%2f%2f',
		'%255c',
		'%%35c',
		'%25%35%63',
		'%c0%af',
		'%c1%9c',
		'%c1%pc',
		'%c0%qf',
		'%c1%8s',
		'%c1%1c',
		'%c1%af',
		'%e0%80%af',
		'%u',
		'+%2F*%21',
		'%27--',
		'%27 --',
		'%27%23',
		'%27 %23',
		'benchmark%28',
		'IDATH.c\<?',
		'IDATH.c??<script',
		'IDATHKc??<script',
		'insert+into+',
		'r3dm0v3',
		'select+1+from',
		'union+all+select',
		'union+select',
		'waitfor+delay+',
		'w00tw00t'
	];
	
	$qs = fw_getQS();
	return fw_needleSearch( $qs, $uri_frags );
}

// Check browser and platform matches
function fw_browserCompat( $ua ) {
	$safari		= fw_has( $ua, 'Safari' );
	$chrome		= fw_has( $ua, 'Chrome' );
	$trident	= fw_has( $ua, 'Trident' );
	
	// Browser can't be Chrome, Safari, *and* Trident
	if ( $chrome && $safari && $trident ) {
		return true;
	}
	
	$edge		= fw_has( $ua, 'Edge' );
	// Edge is not trident
	if ( $edge && $trident ) {
		return true;
	}
	
	$linux		= fw_has( $ua, 'Linux' );
	$mac		= fw_has( $ua, 'Mac OS' );
	$x11		= fw_has( $ua, 'X11' );
	$wow64		= fw_has( $ua, 'WOW64' );
	
	// Wow64 is Windows
	$nix		= $x11 || $linux || $mac;
	if ( $nix && $wow64 ) {
		return true;
	}
	
	// ...But not with Win64
	if ( fw_has( $ua, 'Win64' ) && $wow64 ) {
		return true;
	}
	
	// Fake IE
	if ( fw_has( $ua, 'MSIE' ) && !$trident ) {
		return true;
	}
	
	// Trident (IE) on recent Mac OS is unlikely
	if ( $mac && $trident ) {
		return true;
	}
	
	// Can't be Safari and Trident too
	if ( $safari && $trident ) {
		return true;
	}
	
	$ie10		= fw_has( $ua, 'MSIE 10.' );
	// Can't be both Edge and IE 10 at the same time
	if ( $ie10 && $edge ) {
		return true;
	}
	
	// IE 10 doesn't belong on Windows 10. Compat mode is IE 7
	if ( fw_has( $ua, 'Windows NT 10.' ) && $ie10 ) {
		return true;
	}
	
	// Trident doesn't belong on Nix
	if ( ( $x11 && $trident ) || ( $nix && $trident ) ) {
		return true;
	}
	
	$ie5		= fw_has( $ua, 'MSIE 5' );
	// Very old IE on newish Windows
	if ( $ie5 && $wow64 ) {
		return true;
	}
	
	// Old IE in places it doesn't belong
	if ( ( $ie5 && $trident ) || ( $ie5 && $nix ) ) {
		return true;
	}
	
	// New IE in places it doesn't belong
	if ( $ie10 && $nix ) {
		return true;
	}
	
	// User agent switcher
	if ( 
		fw_has( $ua, 'Windows Phone' ) && 
		fw_has( $ua, 'Android' ) 
	) {
		return true;
	}
	
	return false;
}


// Closer evaluation
function fw_browserCheck( $ua, $val ) {
	// Browsers should send Accept
	if ( !\array_key_exists( 'accept', $val ) ) {
		return true;
	}
	
	$pr	= $_SERVER['SERVER_PROTOCOL'];
	
	// Expect and HTTP/1.0 shouldn't go together
	if (
		fw_has( $pr, 'HTTP/1.0' ) && 
		\array_key_exists( 'expect', $val )
	) {
		return true;
	}
	
	// Repeated "windows", "wow64" etc...
	$rpt	= 'windows|wow64|linux|gecko|apple|android';
	if ( \preg_match( '/(' .$rpt . ')(.*?)(\s+)?\1/i', $ua ) ) {
		return true;
	}
	
	// HTTP/1.1 and Cache behavior mismatch
	if (
		fw_has( $pr, 'HTTP/1.1' ) && 
		fw_has( $val['pragma'] ?? '', 'no-cache' ) && 
		!\array_key_exists( 'cache-control', $val ) 
	) {
		return true;
	}
	
	// Obsolete params
	if ( 
		fw_has( $val['cookie'] ?? '', '$Version=0' )	|| 
		\array_key_exists( 'cookie2', $val )		|| 
		fw_has( $val['range'] ?? '', '=0-' ) 
	) {
		return true;
	}
	
	$mozilla	= fw_startsWith( $ua, [ 'Mozilla' ] );
	if ( $mozilla ) {
		// Long since discontinued
		if ( fw_needleSearch( $ua, [ 'Google Desktop' ] ) ) {
			return true;
		}
	}
	
	// TE sent by IE Mobile, but not Akamai
	if ( \preg_match( '/\bTE\b/i', $val['connection'] ) ) {
		if ( 
			!\array_key_exists( 'akamai-origin-hop', $val ) && 
			fw_needleSearch( $ua, [ 'IEMobile' ] )
		) {
			return true;
		}
	}
	
	return fw_browserCompat( $ua );
}

function fw_botCheck() {
	$ip = fw_getIP();
	
	// Invalid IP?
	if ( empty( $ip ) ) {
		return true;
	}
	
	// Ideally, should be blocked at the router
	static $never	=  [
		"0.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12", 
		"192.0.2.0/24",
		"198.18.0.0/15",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
	];
	
	// Local IP (testing or tor)
	static $localip = [
		"10.0.0.0/8", 
		"127.0.0.0/8",
		"192.168.0.0/16"
	];
	
	// Known search engine ranges
	
	static $google	= [
		"66.249.64.0/19", 
		"64.233.160.0/19", 
		"72.14.192.0/18", 
		"203.208.32.0/19", 
		"74.125.0.0/16", 
		"216.239.32.0/19", 
		"209.85.128.0/17"
	];
	
	static $msn	= [
		"207.46.0.0/16", 
		"65.52.0.0/14", 
		"207.68.128.0/18", 
		"207.68.192.0/20", 
		"64.4.0.0/18", 
		"157.54.0.0/15", 
		"157.60.0.0/16", 
		"157.56.0.0/14", 
		"131.253.21.0/24", 
		"131.253.22.0/23", 
		"131.253.24.0/21", 
		"131.253.32.0/20", 
		"40.76.0.0/14"
	];
	
	static $yahoo	= [
		"202.160.176.0/20", 
		"67.195.0.0/16", 
		"203.209.252.0/24", 
		"72.30.0.0/16", 
		"98.136.0.0/14", 
		"74.6.0.0/16"
	];
	
	static $baidu	= [
		"119.63.192.0/21",
		"123.125.71.0/24",
		"180.76.0.0/16",
		"220.181.0.0/16"
	];
	
	// Martians
	if ( fw_inSubnet( $ip, $never ) ) {
		return true;
	}
	
	// Reserved range?
	if ( !SKIP_LOCAL ) {
		if ( fw_inSubnet( $ip, $localip ) ) {
			return true;
		}
	}
	
	$ua = fw_getUA();
	
	/**
	 *  Search engine checks
	 */
	// Googlebots
	if ( fw_needleSearch( $ua, [ 
		'Googlebot', 
		'Google Web Preview', 
		'Mediapartners-Google' 
	] ) ) {
		if ( !fw_inSubnet( $ip, $google ) ) {
			return true;
		}
	
	// Baidu bot
	} elseif ( fw_needleSearch( $ua, [ 'baidu' ] ) ) {
		if ( !fw_inSubnet( $ip, $baidu ) ) {
			return true;
		}
	
	// Bingbot
	} elseif ( fw_needleSearch( $ua, [ 
		'bingbot', 
		'msnbot', 
		'MS Search' 
	] ) ) {
		if ( !fw_inSubnet( $ip, $msn ) ) {
			return true;
		}
	
	// Yahoo! bot
	} elseif ( fw_needleSearch( $ua, [ 
		'Yahoo! SearchMonkey', 
		'Yahoo! Slurp' 
	] ) ) {
		if ( !fw_inSubnet( $ip, $yahoo ) ) {
			return true;
		}
	}
	
	return false;
}

function fw_getMethod() {
	static $method;
	
	if ( isset( $method ) ) {
		return $method;
	}
	
	$method = 
	\strtolower( trim( $_SERVER['REQUEST_METHOD'] ?? '' ) );
	return $method;
}

function fw_checkReferer( $ref ) {
	$srv	= $_SERVER['SERVER_NAME'] ?? '';
	$verb	= fw_getMethod();
	
	if ( !SKIP_LOCAL && empty( $srv ) && $verb != 'get' ) {
		return true;
	}
	
	// These shouldn't have referer
	if ( \in_array( 
		$verb, 
		[ 'put', 'delete', 'patch', 'options', 'head' ] 
	) ) {
		return true;
	}
	
	$url	= \parse_url( $ref );
	$host	= $url['host'] ?? '';
	
	// Post should only come from current host
	if ( 
		0 == \strcasecmp( 'post', $verb ) && 
		0 != \strcasecmp( $srv, $host ) 
	) {
		return true;
	}
	
	return false;
}

function fw_getHeaders() {
	static $val;
	
	if ( isset( $val ) ) {
		return $val;
	}
	
	$val = [];
	
	foreach ( $_SERVER as $k => $v ) {
		// Skip non-request headers
		if ( 0 !== \strncasecmp( $k, 'HTTP_', 5 ) ) {
			continue;
		}
		
		$a = \explode( '_' , $k );
		
		// Take out 'HTTP'
		\array_shift( $a );
		
		$val[ \strtolower( \implode( '-', $a ) ) ] = $v;
	}
	
	return $val;
}

function fw_headerCheck() {
	$val = fw_getHeaders();
	
	if ( 
		// Must not be used
		\array_key_exists( 'proxy-connection', $val )	|| 
		// This is a response header
		\array_key_exists( 'content-range', $val )	||
		// Suspect request headers
		\array_key_exists( 'x-aaaaaaaaaa', $val )
	) {
		return true;
	}
	
	// Fail, if "referrer" correctly spelled
	if ( \array_key_exists( 'referrer', $val ) ) {
		return true;
	}
	
	// Should not be empty, if set, and must contain a colon (:)
	if ( \array_key_exists( 'referer', $val ) ) {
		$ref	= $val['referer'] ?? '';
		if ( empty( $ref ) ) {
			return true;
		}
		if ( !fw_has( $ref, ':' ) ) {
			return true;
		}
		
		if ( fw_checkReferer( $ref ) ) {
			return true;
		}
	}
	
	// Contradicting or empty connections
	$cn	= $val['connection'];
	if ( ( 
		fw_has( $cn, 'Keep-Alive' ) && 
		fw_has( $cn, 'Close' ) 
	) || empty( $cn ) ) {
		return true;
	}
	
	// Repeated words in connection? E.G. "close, close"
	if ( \preg_match( '/(\w{3,}+)(,|\.)(\s+)?\1/i', $cn ) ) {
		return true;
	}
	
	// Referrer spam
	if ( !empty( $val['via'] ) ) {
		if ( 
			fw_has( $val['via'], 'PCNETSERVER' )	|| 
			fw_has( $val['via'], 'pinappleproxy' ) 
		) {
			return true;
		}
	}
	
	$ua	= fw_getUA();
	
	// Probably not a bot. Then check browser
	return fw_browserCheck( $ua, $val );
}

function fw_sanityCheck() {
	// None of these should be empty
	$pr	= trim( $_SERVER['SERVER_PROTOCOL'] ?? '' );
	$ua	= fw_getUA();
	$mt	= fw_getMethod();
	
	if ( empty( $pr ) || empty( $ua ) || empty( $mt ) ) {
		return true;
	}
	
	// 'HTTP/' without space Should always be in the protocol
	if ( !fw_has( $pr, 'HTTP/' ) ) {
		return true;
	}
	
	// Suspicious UA lengths ("Mozilla/5." alone is 10 characters)
	$ual	= strlen( $ua );
	if ( $ual < 10 || $ual > 300 ) {
		return true;
	}
	
	// Allowed HTTP methods
	switch( fw_getMethod() ) {
		case 'get':
		case 'post':
		case 'head':
		case 'connect':
		case 'options':
		case 'patch':
		case 'delete':
		case 'put':
			return false;
		
		// Unrecognized method (E.G TRACE can be exploited)
		default:
			return true;
	}
}

function fw_insertLog() {
	$db	= fw_getDb();
	$stm	= $db->prepare( \FIREWALL_DB_INSERT );
	$stm->execute( [
		':ip'		=> fw_getIP(), 
		':ua'		=> fw_getUA(), 
		':uri'		=> fw_getQS(), 
		':method'	=> fw_getMethod(), 
		':headers'	=> \implode( "\n", fw_getHeaders() )
	] );
	
	// Close DB Connection
	fw_getDb( true );
}

function fw_start() {
	// Fresh request
	if (
		fw_sanityCheck()	|| 
		fw_uriCheck()		|| 
		fw_botCheck()		|| 
		fw_uaCheck()		|| 
		fw_headerCheck()
	) {
		fw_insertLog();
		
		// Send kill
		fw_instaKill();
	}
}



// Begin Firewall

fw_start();
