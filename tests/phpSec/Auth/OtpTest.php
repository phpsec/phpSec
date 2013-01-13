<?php
class OtpTest extends PHPUnit_Framework_TestCase {


  public function testOtp() {

    $psl = new \phpSec\Core();

    $psl['store'] = $psl->share(function($psl) {
      return new \phpSec\Store\File(sys_get_temp_dir(), $psl);
    });

    $otp = $psl['auth/otp'];

    $pw = $otp->generate('f00');

    $this->assertTrue(strlen($pw) == 6);
    $this->assertFalse($otp->validate($pw, 'baz'));
    $this->assertFalse($otp->validate($pw.'-invalid', 'f00'));
    $this->assertTrue($otp->validate($pw, 'f00'));
    $this->assertFalse($otp->validate($pw, 'f00'));

  }
}