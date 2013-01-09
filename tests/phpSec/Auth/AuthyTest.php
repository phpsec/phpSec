<?php
class AuthyTest extends PHPUnit_Framework_TestCase {


  public function testAuthy() {
    $psl = new \phpSec\Core();


    $authy = $psl['auth/authy'];
    $authy->_apiKey = 'bcdfb7ce5e6854dcfe65ce5dd0d568c7';
    $authy->_sandbox = true;

    $authyID = $authy->userNew('phpsec@example.com', '12345678', '47');

    $this->assertTrue(is_int($authyID));

    $this->assertTrue($authy->verify($authyID, '0000000'));

    $this->assertFalse($authy->verify($authyID, '1234567'));

    $this->assertEquals('AUTHY_SERVER_BAD_OTP', $authy->lastError);


  }
}