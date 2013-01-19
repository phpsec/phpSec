<?php namespace phpSec\Store;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use \phpSec\Crypt\Crypto;
use \phpSec\Common\Core;

/**
 * Class for handling flat file storage.
 * @package phpSec
 */
class File extends Store {

  private $_dataDir  = null;
  public  $_hashType = 'sha256';

  /**
   * phpSec core Pimple container.
   */
  private $psl = null;

  public function __construct($loc, \phpSec\Core $psl) {
    $this->psl = $psl;

    if(!is_writeable($loc)) {
      throw new \phpSec\Exception\IOException('Storage directory('.$loc.') not writeable');
      return false;
    }
    $this->_dataDir = $loc;
    return true;
  }

  public function read($type, $id) {
    $crypto = $this->psl['crypt/crypto'];

    $fileName = $this->fileName($type, $id);
    if(!file_exists($fileName)) {
      return false;
    }
    $data = file_get_contents($fileName);
    list($meta, $data) = explode("\n\n", $data, 2);
    $jsonData = json_decode($meta);

    $mac = $crypto->pbkdf2($data, $id, 1000, 32);

    if($mac != base64_decode($jsonData->mac)) {
      throw new \phpSec\Exception\GeneralSecurityException('Message authentication code invalid while reading store');
      return false;
    }
    return unserialize($data);
  }

  public function write($type, $id, $data) {
    $crypto = $this->psl['crypt/crypto'];

    $fileName =  $this->fileName($type, $id);

    $data = serialize($data);
    $saveData['id']   = base64_encode($id);
    $saveData['mac']  = base64_encode($crypto->pbkdf2($data, $id, 1000, 32));
    $saveData['time'] = time();

    $jsonData = json_encode($saveData);
    $fp = fopen($fileName, 'w');
    if($fp !== false) {
      if(flock($fp, LOCK_EX)) {
        fwrite($fp, $jsonData."\n\n");
        fwrite($fp, $data);
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
      } else {
        throw new \phpSec\Exception\IOException('Could not lock file while writing to store');
      }
    }
    return false;
  }

  public function delete($type, $id) {
    @unlink(self::fileName($type, $id));
  }

  public function listIds($type) {
    $ids = array();
    $files = glob($this->_dataDir.'/store_'.$type.'_*');
    foreach($files as $file) {
      $data = file_get_contents($file);

      list($meta, $data) = explode("\n\n", $data, 2);
      $jsonData = json_decode($meta);
      $ids[] = base64_decode($jsonData->id);

    }
    return $ids;
  }

  public function meta($type, $id) {
    $fileName = $this->fileName($type, $id);
    if(!file_exists($fileName)) {
      return false;
    }
    $data = file_get_contents($fileName);
    list($meta, $data) = explode("\n\n", $data, 2);

    $data = json_decode($meta);
    $data->id  = base64_decode($data->id);
    $data->mac = base64_decode($data->mac);
    return $data;
  }

  /**
   * Generate a unique filename.
   *
   * @param string $type
   *   Type of data.
   *
   * @param string $id
   *   Id of the storage object.
   *
   * @return string
   *   Filename.
   */
  private function fileName($type, $id) {
    return $this->_dataDir.'/store_'.$type.'_'.hash($this->_hashType, $id);
  }
}