<?php
require_once 'phpsec.class.php';

class XssFilterTest extends PHPUnit_Framework_TestCase {
  public function setUp(){
  }
  public function tearDown(){
  }
  public function testHtmlStrip()  {
    $string = phpsec::f(
      'This is a %test.',
      array('%test' => '<br>test')
    );
    $this->assertEquals($string, 'This is a test.');
  }

  public function testEscaping()  {
    $string = phpsec::f(
      'This is a !test.',
      array('!test' => '<br>"test"')
    );
    $this->assertEquals($string, 'This is a &lt;br&gt;&quot;test&quot;.');
  }

  public function testHtmlEscaping()  {
    $string = phpsec::f(
      'This is a @test.',
      array('@test' => '<br>"test"')
    );
    $this->assertEquals($string, 'This is a &lt;br&gt;"test".');
  }
}