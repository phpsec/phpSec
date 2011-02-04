<?php
/**
      phpSec - A PHP security library
      Web:     https://github.com/xqus/phpSec

      Copyright 2011 Audun Larsen. All rights reserved.
      larsen@xqus.com

   Redistribution and use, with or without modification,
   are permitted provided that the following condition is met:

   * Redistribution and use of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

   THIS SOFTWARE IS PROVIDED BY ``AS IS''
   IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY TYPE OF
   DAMAGE ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE.


 */


echo "<pre>";
error_reporting(E_ALL);
ini_set('display_errors','stdout');

require_once 'phpsec.class.php';


// Print the uid
echo 'Uid: '.phpsec::$uid."\n\n";
echo "<hr />";


/**
 * Test randomness
 */
echo phpsec::randBytes(10);
echo "<hr />";
/**
 * Test encryption
 */
print_r(phpsec::encrypt('f00bar'));
print_r(phpsec::decrypt(phpsec::encrypt(array('1','2'))));
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
    echo "Valid token!";
  } else {
    echo "Invalid token!";
  }
}
$token = phpSec::getToken('myform');
echo "<form>";
echo "<input type='hidden' name='token' value='$token'>";
echo "<input type='submit' name='do'>";
echo "</form>";
echo "<hr />";

/**
 * Test XSS filter.
 */
echo phpsec::f('This is a !test, %ok?', array('!test' => 't<br>est. Å?""', '%ok' => 'o<br>kÅ?""'));
/**
 * Test logging.
 */
phpsec::log('access', 'Someone loaded the page', 'debug');


echo "</pre>";
?>
