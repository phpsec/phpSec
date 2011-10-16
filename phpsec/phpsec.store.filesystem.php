<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/xqus/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

class phpsecStoreFilesystem extends phpsecStore {

  private $_dataDir  = null;
  public  $_hashType = 'sha256';

  public function __construct($loc) {
    if(!is_writeable($loc)) {
      phpsec::error('Storage directory('.$loc.') not writeable');
      return false;
    }
    $this->_dataDir = $loc;
    return true;
  }

  public function read($type, $id) {
    $fileName =  $this->fileName($type, $id);
    if(!file_exists($fileName)) {
      return false;
    }
    $data = json_decode(file_get_contents($fileName));
    $mac = phpsecCrypt::pbkdf2($data->data, $id, 1000, 32);

    if($mac != base64_decode($data->mac)) {
      phpsec::error('Message authentication code invalid while reading store');
      return false;
    }
    return unserialize(base64_decode($data->data));
  }

  public function write($type, $id, $data) {
    $fileName =  $this->fileName($type, $id);
    $saveData['id']   = base64_encode($id);
    $saveData['data'] = base64_encode(serialize($data));
    $saveData['mac']  = base64_encode(phpsecCrypt::pbkdf2($saveData['data'], $id, 1000, 32));

    $data = json_encode($saveData);
    $fp = fopen($fileName, 'w');
    if($fp !== false) {
      if(flock($fp, LOCK_EX)) {
        fwrite($fp, $data);
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
      } else {
        self::error('Could not lock logfile while writing to store');
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
      $data = json_decode(file_get_contents($file));
      $ids[] = base64_decode($data->id);

    }
    return $ids;
  }

  private function fileName($type, $id) {
    return $this->_dataDir.'/store_'.$type.'_'.hash($this->_hashType, $id);
  }
}