phpSec changelog
================

beta-0.4
--------
* [#83] Added class phpsecOtpcard and moved PS OTP functionality from phpsecOtp
   to it.
* [#84, #85] Improvements to phpsecOtp.

beta-0.3: January 4. 2012 - xqus
--------------------------------
* [#66] phpSec can now run without storage configured.
* [#58] phpsecCrypt now pads data by default.
* [#81] phpsecPw now supports PBKDF2, and uses it as default.
* Added new password hashing class: phpsecHash. phpsecPw should not be used
  anymore.
* Fixed phpsecFilter::f().

beta-0.2: December 21. 2011 - xqus
----------------------------------
* [#43] Implemented PKCS7 padding in phpsecCrypt.
* [#62] Added phpsec::arrayCheck().
* [#63] Improved checking of json data passed to phpSec.
* Fixed call to error method in phpsecPw::check()
* [#51] phpsecPw now uses a binary salts.
* phpsecPw::age() removed.
* [#50] Session handler now uses a binary key to encrypt session data.
* [#42] Added mySQL support.
* Yubikey integration not considered experimental anymore.
  * [#48, #49] Improvements of the Yubikey integration.
  * [#75] Fixed: phpsecYubikey::getYubikeyId() could retrive wrong ID.
  * [#76] Fixed: phpsecYubikey::validOtp() to strict.
  * [#74] Fixed: phpsecYubikey::getResponse(): Number of attempts and timeout
          should be possible to configure.


beta-0.1: November 7. 2011 - xqus
---------------------------------
* [#33, #34]phpsec::f() is now phpsec::t(), and phpsec::f() is a simple XSS
  filter method.
* Removed the examples.php from source. See the online manual for examples:
  http://phpsec.xqus.com/manual
* Don't use session_regenerate_id() anymore, since it causes many bugs.
* Generate a stronger PHP session ID.
* [#30] Improve session hijacking protection.
* Improved the password hashing methods.
* Changed default encryption algorithm to RIJNDAEL-256.
* Added implemention of PBKDF2 as described in RFC 2898.
* Create a PBKDF2 MAC to ensure message integrity in phpsecCrypt. This breaks
  compability with older versions of phpSec.
* [#37] phpsecCrypt don't modify the encryption key anymore.
* Regenerate session ID in custom session handler.
* Stronger keys for encryption of session.
* Better error handling in phpSecCrypt.
* [#38] Storage class for general data storage for all sub-classes.
* [#41] Separate password, token and filter methods from core.
* Many minor fixes..

alpha-0.0.5: August 14. 2011 - xqus
-----------------------------------
* Added phpsecRand::arrayRand(): Method to select random keys from an array.
* Fixed bug in key generation method in phpsecCrypt().
  This means that data encrypted with phpSec alpha-0.0.4 and older will not
  decrypt in this version.

alpha-0.0.4: July 11. 2011 - xqus
---------------------------------
* [#25] Empty CSRF token creates hickups.
* Added initial GPG/PGP support. Still experimental.
* Added phpsecLog class to add better logging support.
  This means that phpsec::init() has to be called before setting the log dir:
  phpsecLog::$_logdir = 'filesystem:/var/www/phpSec/logs';
  Also phpsec::log() is now phpsecLog::log().
* Added syslog support to phpsecLog.
* phpsec::f() now accepts strings a array of data to filter.
* Improved error handling.
* phpsecCrypt::encrypt() performance improvements.
* Greatly improved key generation security in phpsecCrypt().
  This means that data encrypted with phpSec alpha-0.0.3 and older will not
  decrypt in this version.

alpha-0.0.3: March 9. 2011 - xqus
---------------------------------
* [#21] Use of phpSec session handler is now optional.
* [#17] phpsec::pwHash() now returns a JSON encoded array.
* Added Yubikey integration. See https://github.com/xqus/phpSec/wiki/Yubikey
* Added &type variables to phpsec::f().
* Many minor fixes..

alpha-0.0.2: February 5. 2011 - xqus
------------------------------------
* The library is no longer automatically initialized.
  You now need to call phpsec::init().
* Added encryption functions.
* Added random functions.
* Separated the library into smaller files.
* Added session encryption.
* Many minor changes..

Prealpha 0.0.1: January 16. 2011 - xqus
---------------------------------------

January 8. 2011 - xqus
----------------------
* First code written.
