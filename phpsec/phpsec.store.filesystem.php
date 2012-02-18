<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 *  Class for handling flat file storage.
 */
class phpsecStoreFilesystem extends phpsecStore {

  private $_dataDir  = null;
  public  $_hashType = 'sha256';

  /**
   * @see phpsecStore::__construct()
   */
  public function __construct($loc) {
    if(!is_writeable($loc)) {
      phpsec::error('Storage directory('.$loc.') not writeable', E_USER_ERROR);
      return false;
    }
    $this->_dataDir = $loc;
    return true;
  }

  /**
   * @see phpsecStore::read()
   */
  public function read($type, $id) {
    $fileName = $this->fileName($type, $id);
    if(!file_exists($fileName)) {
      return false;
    }
    $data = file_get_contents($fileName);
    list($meta, $data) = explode("\n\n", $data, 2);
    $jsonData = json_decode($meta);

    $mac = phpsecCrypt::pbkdf2($data, $id, 1000, 32);

    if($mac != base64_decode($jsonData->mac)) {
      phpsec::error('Message authentication code invalid while reading store');
      return false;
    }
    return unserialize($data);
  }

  /**
   * @see phpsecStore::write()
   */
  public function write($type, $id, $data) {
    $fileName =  $this->fileName($type, $id);

    $data = serialize($data);
    $saveData['id']   = base64_encode($id);
    $saveData['mac']  = base64_encode(phpsecCrypt::pbkdf2($data, $id, 1000, 32));
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
        phpsec::error('Could not lock file while writing to store');
      }
    }
    return false;
  }

  /**
   * @see phpsecStore::delete()
   */
  public function delete($type, $id) {
    @unlink(self::fileName($type, $id));
  }

  /**
   * @see phpsecStore::listIds()
   */
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

  /**
   * @see phpsecStore::meta()
   */
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