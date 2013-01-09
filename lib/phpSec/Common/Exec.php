<?php namespace phpSec\Common;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use \phpSec\Common\Core;

/**
 * Execute external programs in a safe(er) way.
 * @package phpSec
 */
class Exec {

  const STDIN  = 0;
  const STDOUT = 1;
  const STDERR = 2;

  private $descSpecs = array(
      self::STDIN  => array("pipe", "r"),
      self::STDOUT => array("pipe", "w"),
      self::STDERR => array("pipe", "w"),
    );

  /**
   * Array containing additional ENV variables.
   */
  public $_env = array();

  /**
   * Current Working Directory.
   * Defaults to where the script is located.
   */
  public $_cwd = null;

  /**
   * Execute an external program.
   *
   * This method uses as PDO like syntax to build commands.
   *
   * @param string $cmd
   *   Command to execute. If you need to pass arguments to a command. A PDO like syntax can be used.
   *   For example: "ls -lsa %path".
   *
   * @param array $args
   *   An associative array containing the arguments to pass to $cmd.
   *   For example: array('%path' => '/home');
   *
   * @param string $stdin
   *   If the command requests input (e.g. a passphrase) this can be
   *   passed here. Note that if a command requires multiple feedbacks
   *   from a user this method can not be used.
   *
   * @return array
   *   Returns an array containing return value and results from STDOUT and STDERR.
   */
  public function run($cmd, $args = array(), $stdin = null) {

    $cmd = $this->buildCommand($cmd, $args);

    $process = proc_open($cmd, $this->descSpecs, $pipes, $this->_cwd, $this->_env);

    if(is_resource($process)) {

      /* Write stuff to STDIN, and close it. */
      fwrite($pipes[self::STDIN], $stdin);
      fclose($pipes[self::STDIN]);

      /* Read STDOUT and STDERR. */
      $out['STDOUT'] = stream_get_contents($pipes[self::STDOUT]);
      $out['STDERR'] = stream_get_contents($pipes[self::STDERR]);

      /* Close STDOUT and STDERR to aviod potential deadlocks. */
      fclose($pipes[self::STDOUT]);
      fclose($pipes[self::STDERR]);

      /* Close process and get return value. */
      $out['return'] = proc_close($process);

      return $out;
    }
    return false;
  }

  /**
   * Builds a command that is safe to execute.
   *
   * @param string $cmd
   *   Base command (with placeholders) to execute.
   *
   * @param array $args
   *   An associative array containing data to filter.
   *
   * @return string
   *   Returns a command that is safe to execute.
   */
  private function buildCommand($cmd, $args = array()) {
    while(list($name, $data) = each($args)) {
    $safeData = false;
      $filterType = mb_substr($name, 0, 1);
      switch($filterType) {
        case '%':
          $safeData = escapeshellarg($data);
          break;
        case '!':
          $safeData = escapeshellcmd($data);
          break;
        default:
          throw new \phpSec\Exception\InvalidArgumentException('Unknown variable type');
          break;
      }
      if($safeData !== false) {
        $cmd = str_replace($name, $safeData, $cmd);
      }
    }
    return $cmd;
  }
}
