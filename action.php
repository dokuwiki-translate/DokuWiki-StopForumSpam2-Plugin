<?php
/**
 * StopForumSpam Plugin - Action Section
 * 
 * A part of the system is inspired by IPBan plugin (https://github.com/splitbrain/dokuwiki-plugin-ipban)
 * 
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     HokkaidoPerson <dosankomali@yahoo.co.jp>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();
if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');
require_once(DOKU_PLUGIN.'action.php');

class action_plugin_stopforumspam2 extends DokuWiki_Action_Plugin {

    function register(Doku_Event_Handler $controller){
        $controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'accessdenial', array());
        $controller->register_hook('TPL_CONTENT_DISPLAY', 'BEFORE', $this, 'ipprevent', array());
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'elementcheck', array());
    }

    function accessdenial(&$event, $param){
        $helper = plugin_load('helper','stopforumspam2');

        if ($helper->quickipcheck(null, $this->getConf('accessRefusalFreq'), $this->getConf('accessRefusalConf'))) {
            $text = $this->locale_xhtml('banned');
            $title = $this->getLang('denied');
            header("HTTP/1.0 403 Forbidden");
            echo<<<EOT
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head><title>$title</title></head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<body style="font-family: Arial, sans-serif">
  <div style="width:60%; margin: auto; background-color: #fcc;
              border: 1px solid #faa; padding: 0.5em 1em;">
  $text
  </div>
</body>
</html>
EOT;
        exit;
        }
    }

    function ipprevent(&$event, $param) {
        global $ACT;
        $helper = plugin_load('helper','stopforumspam2');
        if ($ACT == 'edit' and $helper->quickipcheck(null, $this->getConf('protectEditFreq'), $this->getConf('protectEditConf'))) {
            echo $this->locale_xhtml('bannededit');
            $event->preventDefault();
        }
        if ($ACT == 'register' and $helper->quickipcheck(null, $this->getConf('protectRegFreq'), $this->getConf('protectRegConf'))) {
            echo $this->locale_xhtml('bannedreg');
            $event->preventDefault();
        }
    }

    function elementcheck(&$event, $param) {
        global $conf;
        $helper = plugin_load('helper','stopforumspam2');
        $iplogname = $conf['cachedir'] . '/stopforumspam2_' . $_SERVER['REMOTE_ADDR'] . '.txt';
        $expiremin = $this->getConf('preventNuisanceReg');

        if ($event->data['type'] == 'create') {
            if ($expiremin != 0) {
                if (file_exists($iplogname)) {
                    $logdate = file_get_contents($iplogname);
                    $current = time();
                    $expire = $expiremin * 60;
                    if ($current - $logdate > $expire) {
                        unlink($iplogname);
                    } else {
                        $string = sprintf($this->getLang('beinglisted'), round(($logdate + $expire - $current) / 60, 1));
                        msg($string, -1);
                        $event->preventDefault();
                        return;
                    }
                }
            }

            $username = $event->data['params'][2];
            $email = $event->data['params'][3];
            $result1 = $helper->freqcheck(null, $email, $username, FALSE, $this->getConf('protectRegFreq'));
            $result2 = $helper->confcheck(null, $email, $username, FALSE, $this->getConf('protectRegConf'));

            if ($result1 or $result2) {
                msg($this->getLang('spammyelementreg'), -1);
                if ($expiremin != 0) {
                    $handle = @fopen($iplogname, 'w');
                    if ($handle) {
                        $string = sprintf($this->getLang('listed'), $expiremin);
                        if (fwrite($handle, time()) !== FALSE) msg($string, -1);
                        fclose($handle);
                    }
                }
                $event->preventDefault();
            }
        }
    }

}
