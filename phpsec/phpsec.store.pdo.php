<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 *  Class for handling database storage.
 */
class phpsecStorePdo extends phpsecStore {

  public  $_hashType = 'sha256';
  private $dbh       = null;
  private $table     = null;

  public function __construct($loc) {
    /* Separate username and password from DSN */
    $parts = phpsecStorePdo::parseDsn($loc);
    $loc   = 'mysql:dbname='.$parts['dbname'].';host='.$parts['host'];

    try {
      $this->dbh = new PDO($loc, $parts['username'], $parts['password']);
    } catch(PDOException $e) {
      phpsec::error('Database connection failed: ' . $e->getMessage(), E_USER_ERROR);
      return false;
    }
    $this->table = $parts['table'];

    $storeTable = array(
      array(
        'Field'   => 'type',
        'Type'    => 'varchar(255)',
        'Null'    => 'NO',
        'Key'     => 'MUL',
        'Default' => NULL,
        'Extra'   => '',
      ),
      array(
        'Field'   => 'id',
        'Type'    => 'varchar(255)',
        'Null'    => 'NO',
        'Key'     => 'PRI',
        'Default' => NULL,
        'Extra'   => '',
      ),
      array(
        'Field'   => 'mac',
        'Type'    => 'binary(32)',
        'Null'    => 'NO',
        'Key'     => '',
        'Default' => NULL,
        'Extra'   => '',
      ),
      array(
        'Field'   => 'time',
        'Type'    => 'int(11) unsigned',
        'Null'    => 'NO',
        'Key'     => '',
        'Default' => NULL,
        'Extra'   => '',
      ),
      array(
        'Field'   => 'data',
        'Type'    => 'text',
        'Null'    => 'NO',
        'Key'     => '',
        'Default' => NULL,
        'Extra'   => '',
      ),
    );


    $sth = $this->dbh->prepare(
      'DESCRIBE `'.addslashes($this->table).'`'
    );
    $sth->execute(array());

    $currentStructure = $sth->fetchAll(PDO::FETCH_ASSOC);

    if(sizeof($currentStructure) !== sizeof($storeTable)) {
      phpsec::error('Invalid table ('.$parts['dbname'].'.'.$this->table.') structure', E_USER_ERROR);
      return false;
    }

    for($i=0; $i < sizeof($storeTable); $i++) {
      $diff = array_diff_assoc($currentStructure[$i], $storeTable[$i]);
      if(sizeof($diff) > 0) {
        phpsec::error('Invalid table ('.$parts['dbname'].'.'.$this->table.') structure. '.var_export($diff, true), E_USER_ERROR);
        return false;
      }
    }




    return true;
  }

  public function read($type, $id) {
    $sth = $this->dbh->prepare(
      'SELECT * FROM '.$this->table.' WHERE type = :type AND id = :id LIMIT 1'
    );

    $data = array(
      'id'    => $id,
      'type'  => $type,
    );
    $sth->execute($data);

    $data = $sth->fetchAll(PDO::FETCH_ASSOC);

    if(!isset($data[0])) {
      return false;
    }

    $mac = phpsecCrypt::pbkdf2($data[0]['data'], $id, 1000, 32);

    if($mac != $data[0]['mac']) {
      phpsec::error('Message authentication code invalid while reading store');
      return false;
    }
    return unserialize($data[0]['data']);
  }

  public function write($type, $id, $data) {
    $this->delete($type, $id);
    $sth = $this->dbh->prepare(
      'INSERT INTO '.$this->table.' (`id`, `mac`, `time`, `type`, `data`)' .
      'VALUES(:id, :mac, :time, :type, :data)'
    );

    $data = serialize($data);
    $mac  = phpsecCrypt::pbkdf2($data, $id, 1000, 32);

    $data = array(
      'id'   => $id,
      'mac'  => $mac,
      'time' => time(),
      'type' => $type,
      'data' => $data,
    );

    $sth->execute($data);

  }

  public function delete($type, $id){
    $sth = $this->dbh->prepare(
      'DELETE FROM '.$this->table.' WHERE type = :type AND id = :id'
    );

    $data = array(
      'id'   => $id,
      'type' => $type,
    );

    $sth->execute($data);
  }

  public function listIds($type) {
    $ids = array();

    $sth = $this->dbh->prepare(
      'SELECT * FROM '.$this->table.' WHERE type = :type'
    );

    $data = array(
      'type' => $type,
    );

    $sth->execute($data);

    $rows = $sth->fetchAll(PDO::FETCH_ASSOC);
    foreach($rows as $row) {
      $ids[] = $row['id'];
    }
    return $ids;
  }

  public function meta($type, $id) {
    $sth = $this->dbh->prepare(
      'SELECT * FROM '.$this->table.' WHERE type = :type AND id = :id'
    );

    $data = array(
      'id'   => $id,
      'type' => $type,
    );

    $sth->execute($data);

    $rows = $sth->fetchAll(PDO::FETCH_ASSOC);
    if(isset($rows[0])) {
      $obj = object();
      $obj->id   = $rows[0]['id'];
      $obj->mac  = $rows[0]['mac'];
      $obj->time = $rows[0]['time'];

      return $obj;
    } else {
      return false;
    }
  }

  private static function parseDsn($dsn) {
    $parsed = array();
    $parts = explode(';', $dsn);

    foreach($parts as $part) {
      list($key, $val) = explode('=', $part);
      $parsed[$key] = $val;
    }

    return $parsed;
  }
}