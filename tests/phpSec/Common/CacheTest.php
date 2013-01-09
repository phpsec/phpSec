<?php
class CacheTest extends PHPUnit_Framework_TestCase {


  public function testCache() {
    $psl = new \phpSec\Core();

    $psl['store'] = $psl->share(function($psl) {
      return new \phpSec\Store\File(sys_get_temp_dir(), $psl);
    });

    $cache = $psl['cache'];

    $this->assertTrue($cache->cacheSet('name', 'data', 3));

    $data = $cache->cacheGet('name');
    $this->assertEquals('data', $data);
    sleep(4);
    $this->assertFalse($cache->cacheGet('name'));

  }
}