<?php
error_reporting(E_ALL);
ini_set('display_errors','stdout');

include 'xtest/xtest.class.php';
require_once 'phpSec/phpsec.class.php';
require_once 'phpSec/phpsec/phpsec.rand.php';
require_once 'phpSec/phpsec/phpsec.cache.php';
require_once 'phpSec/phpsec/phpsec.crypt.php';
require_once 'phpSec/phpsec/phpsec.session.php';


phpsec::$_datadir = '/tmp';
phpsec::$_logdir  = '/tmp';
phpsec::init();


$test = new xtest();


$rnd = phpsecRand::bytes(10);
/* phpsecRand:Bytes */
$test->assert('true', strlen((binary) $rnd) == 10);

$string = phpsec::f(
  'This is a %test.',
  array('%test' => '<br>test')
);
/* phpsecFilter:Strip HTML */
$test->assert('true', $string == 'This is a test.');

$string = phpsec::f(
  'This is a !test.',
  array('!test' => '<br>"test"')
);
/* phpsecFilter:Escape Special Chars */
$test->assert('true', $string == 'This is a &lt;br&gt;&quot;test&quot;.');

$string = phpsec::f(
  'This is a @test.',
  array('@test' => '<br>"test"')
);
/* phpsecFilter:Escape HTML */
$test->assert('true', $string == 'This is a &lt;br&gt;"test".');

$hash = phpsec::pwHash('123abc');
/* phpsecHash:Valid JSON */
$test->assert('true', $hash !== null);

$data = json_decode($hash, true);
/* phpsecHash:Valid JSON decoded(hash) */
$test->assert('arrayHasKey', $data, 'hash');

/* phpsecHash:Valid JSON decoded(salt) */
$test->assert('arrayHasKey', $data, 'salt');

/* phpsecHash:Valid JSON decoded(algo) */
$test->assert('arrayHasKey', $data, 'algo');

/* phpsecHash:Valid JSON decoded(injection) */
$test->assert('arrayHasKey', $data, 'injection');

/* phpsecHash:Valid Pass */
$test->assert('true', phpsec::pwCheck('123abc', $hash));

/* phpsecHash:Invalid Pass */
$test->assert('false', phpsec::pwCheck('kjl123abc', $hash));

$token = phpsec::getToken('test');

/* phpsecToken:Get token */
$test->assert('true', is_string($token));

/* phpsecToken:Valid token */
$test->assert('true', phpsec::validToken('test', $token));

/* phpsecToken:Token removed */
$test->assert('false', phpsec::validToken('test', $token));

$test->result2term();