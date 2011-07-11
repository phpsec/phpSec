<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@gmail.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/xqus/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */


echo "<pre>";
error_reporting(E_ALL);
ini_set('display_errors','stdout');

require_once 'phpsec.class.php';
phpsec::$_datadir = '/var/www/phpSec/data';
phpsec::init();



/* Test GPG. */
phpsecPgp::$_keyDir = "/tmp/.gnupg";
//echo phpsecPgp::genKeys('Audun Larsen', 'larsen@xqus.com', 'Test', '123abc');


echo "<hr />";

// Print the uid
echo 'Uid: '.phpsec::$uid."\n\n";
echo "<hr />";

/**
 * Test OTP
 */
$otp = phpsecOtp::generate('login');
if(phpsecOtp::validate($otp, 'login')) {
  echo "Valid OTP.";
}
echo "<hr />";
echo phpsecOtp::cardRemaining('5baaabf1cbee');
echo phpsecOtp::cardSelect('5baaabf1cbee');
//$cardId = phpsecOtp::cardGenerate();
if(phpsecOtp::cardValidate('5baaabf1cbee', 63, '7al9p8')) {
  echo "Valid ps OTP.";
}
//print_r(phpsecOtp::cardLoad('5baaabf1cbee'));


echo "<hr />";
/**
 * Test encryption
 */
$encrypted = phpsecCrypt::encrypt(array('secret'=> 'Some secret.'), '675hgjhg786t786786tuygjhgjhgjhg76iuhlkfgdgsfgølø-jkgfgssdasdasd');
print_r($encrypted);
print_r(phpsecCrypt::decrypt($encrypted, '675hgjhg786t786786tuygjhgjhgjhg76iuhlkfgdgsfgølø-jkgfgssdasdasd'));
echo "<hr />";

/**
 * Test captcha.
 */
/*$captcha = phpsec::captcha();
echo "<img src='data/filename.png'>";
echo "<hr />";*/

/**
 * Test the password hasing helper functions.
 */
$pwHashed = phpsec::pwHash('123abc');
echo $pwHashed."\n"; // This is what we save to the database to validate against later.
if(phpsec::pwCheck('123abc', $pwHashed)) {
  echo "Valid password.";
} else {
  echo "Invalid password.";
}
echo "<hr />";

/**
 * Test CSRF tokens
 */
if(isset($_GET['do'])) {
  if(phpsec::validToken('myform', $_GET['token'])) {
    phpsecYubikey::$_clientId     = 5118;
    phpsecYubikey::$_clientSecret = 'n7cIJF1IaL8WeTUsluWRSpRLOqs=';
    if(phpsecYubikey::verify($_GET['otp'])) {
      echo "Valid OTP!";
    } else {
      echo phpsecYubikey::$lastError;
    }
  } else {
    echo "Invalid token!";
  }
}
$token = phpSec::getToken('myform');
echo "<form>";
echo "<input type='hidden' name='token' value='$token'>";
echo "<input type'text' name='otp'>";
echo "<input type='submit' name='do'>";
echo "</form>";
echo "<hr />";

/**
 * Test XSS filter.
 */
echo phpsec::f('http://www.example.com/q=&q', array('&q' => 'this is a query&'));
echo "<hr />";
echo phpsec::f('!', 'this is a query&<hr>');
/**
 * Test logging.
 */
phpsecLog::$_logdir = 'filesystem:/var/www/phpSec/logs';
phpsecLog::log('access', 'Someone loaded the page', LOG_EMERG);

phpsecLog::$_logdir = 'syslog:'.LOG_USER;
phpsecLog::log('access', 'Someone loaded the page', LOG_EMERG);

echo "</pre>";
?>
