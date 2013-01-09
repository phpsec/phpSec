<?php
class ExecTest extends PHPUnit_Framework_TestCase {


  public function testExec() {
    $psl = new \phpSec\Core();
    $exec = $psl['common/exec'];

    $return = $exec->run('php', array(), '<?php echo "Hello World";');

    $this->assertEquals($return['STDOUT'], 'Hello World');
    $this->assertEquals($return['STDERR'], '');
    $this->assertEquals($return['return'], 0);



  }
}