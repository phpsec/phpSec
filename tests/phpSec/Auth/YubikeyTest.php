<?php
class YubikeyTest extends PHPUnit_Framework_TestCase {


  public function testOtp() {

    $psl = new \phpSec\Core();

    $yubikey = $psl['auth/yubikey'];

    $yubikey->clientId     = '5118';
    $yubikey->clientSecret = 'n7cIJF1IaL8WeTUsluWRSpRLOqs=';

    $otp = 'cccccccbdfgkjubfnjvuiibnulrhrigjvrukbdbevibt';

    $this->assertTrue($yubikey->validOtp($otp));
    $this->assertFalse($yubikey->validOtp($otp.' '));
    $this->assertEquals('cccccccbdfgk', $yubikey->getYubikeyId($otp));

    $response = $yubikey->verify($otp);

    $this->assertEquals('YUBIKEY_SERVER_REPLAYED_OTP', $yubikey->lastError);
  }
}