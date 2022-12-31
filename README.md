# Firewall
A single file speed bump to bots and malicious traffic

Firewall is a companion project intended to function as a barrier to abusive requests and malicious bots.

Firewall runs before any other application code. Set the SKIP_LOCAL constant to be defined in your code to prevent this file from being called on its own. 

```
define( 'SKIP_LOCAL', 0 );
require( 'firewall.php' );
```

This setting enables checking for private IP ranges. Use `define( 'SKIP_LOCAL', 1 );` instead to skip checking private ranges if your site is hosted on a private IP range or over Tor.

Firewall will keep track of blocked traffic in the firewall.db file in a writable directory, if the FIREWALL_DB_LOG setting is 1 or you can keep it off by leaving it as 0.

A lot of this was inspired by the [Bad Behavior](http://bad-behavior.ioerror.us) package but does not use the same code.

The [plugin](https://github.com/cypnk/Bare-Plugins/tree/master/firewall) version of this is available for [Bare](https://github.com/cypnk/Bare)
