<?php
/**
      phpSec - A PHP security library
      Web:     https://github.com/xqus/phpSec

      Copyright (c) 2011 Audun Larsen <larsen@xqus.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
 */

/**
 * Implements a session handler to save session data encrypted.
 */
class phpsecSession {
  /**
   * Initialize a phpSec enforced session.
   */
  public static function sessionStart() {
    if(session_id() != '') {
      self::error('Session already started. Can\'t use phpSec sessions', PHPSEC_E_WARN);
    } else {
      /* TODO: Create own session handler and add encryption support.
       * Set the session.save.path to our datadir. */
      session_save_path(PHPSEC_DATADIR);
      /* Rename the session to avoid clusterfu*ks. */
      session_name(PHPSEC_SESSNAME);
      /* Initialize the session. */
      session_start();
      /* Regenerate the session ID and remove the old session to avaoid session hijacking. */
      session_regenerate_id(true);
    }
  }
}
