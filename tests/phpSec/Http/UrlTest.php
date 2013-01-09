<?php
class UrlTest extends PHPUnit_Framework_TestCase {


  public function testUrl() {
    $psl = new \phpSec\Core();

    $url = $psl['http/url'];

    $uri = $url->create('http://example.com/test/file.png');

    $this->assertTrue($url->verify($uri));

    $this->assertFalse($url->verify('http://example.com/test/file.png'));
  }
}