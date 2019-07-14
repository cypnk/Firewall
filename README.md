# Firewall
A single file speed bump to bots and malicious traffic

Firewall is a companion project intended to function as a barrier to  
abusive requests and malicious bots.

Firewall runs before any other application code and it requries only a  
single write-enabled directory to function.

Set the SKIP_LOCAL constant to be defined in your code to prevent this  
file from being called on its own. Firewall will keep track of your  
traffic in the firewall.db file in the writable directory.

A lot of this was inspired by the [Bad Behavior](http://bad-behavior.ioerror.us) package but does not use  
the same code.
