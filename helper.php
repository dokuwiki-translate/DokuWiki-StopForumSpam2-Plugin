<?PHP
/**
 * StopForumSpam2 Plugin - Helper Section
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     HokkaidoPerson <dosankomali@yahoo.co.jp>
 */

if(!defined('DOKU_INC')) die();


class helper_plugin_stopforumspam2 extends DokuWiki_Plugin {

    /**
     * Return the raw result of the investigation
     *
     * @param string or array $ip - Do nothing about the IP address if empty
     * @param string or array $email - Do nothing about the e-mail address if empty
     * @param string or array $username - Do nothing about the user name if empty
     * @param string $wildcards - Specify the wildcards if necessary.  Create the string of wildcards divided by "&".  DO NOT specify serialised formatting wildcards such as 'serial', or the function will not run properly.  e.g.: 'nobadusername'  e.g.: 'nobadip&nobademail&notorexit'
     * @return array - The array contains the whole data returned (converted from the json data to the array).  See https://www.stopforumspam.com/usage
     */
    function rawdata($ip = null, $email = null, $username = null, $wildcards = null){
        // All arguments are empty?  Completely nothing to do.  Return the empty array.
        if ($ip == null and $email == null and $username == null) return array();

        // The script below was adopted from https://www.stopforumspam.com/usage
        // setup the URL
        $data = array(
            'ip' => $ip,
            'username' => $username,
            'email' => $email,
        );

        $data = http_build_query($data, '', '&', PHP_QUERY_RFC3986);
        if ($wildcards != null) $data .= '&' . preg_replace('/[^a-z0-9&=]+/', '', $wildcards);

        // init the request, set some info, send it and finally close it
        $this->ch = curl_init();
        if ($this->ch) {
            curl_setopt ($this->ch, CURLOPT_URL, 'http://api.stopforumspam.org/api?json');
            curl_setopt ($this->ch, CURLOPT_POST, 1);
            curl_setopt ($this->ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt ($this->ch, CURLOPT_RETURNTRANSFER, true);

            $result = curl_exec($this->ch);
            curl_close($this->ch);
        }
        // End of adoption from https://www.stopforumspam.com/usage
        return json_decode($result, true);
    }

    /**
     * Look for the frequency score of given IP address, e-mail address, and(or) user name
     *
     * @param string $ip - Do nothing about the IP address if empty
     * @param string $email - Do nothing about the e-mail address if empty
     * @param string $username - Do nothing about the user name if empty
     * @param boolean $returnvalue - If true, this function returns the frequency score itself.  If false, it checks whether or not the score is as large as or higher than $border.  This will be TRUE if one or more of the IP, e-mail, and user name is likely a spammer.
     * @param value $border - The conf "freqBorder" will be used if empty or minus value.  If $returnvalue is TRUE, the $border will be no use.  Don't check if 0.
     * @return boolean (if $returnvalue is false) or array (otherwise) - The boolean will be TRUE if the user is regarded as a spammer, or FALSE otherwise.  The array's components will be values with keys "ip", "email", and "username".  If the plugin fail to read the frequency, the value will be -1.
     */
    function freqcheck($ip = null, $email = null, $username = null, $returnvalue = FALSE, $border = null){
        global $INFO;

        // All arguments are empty?  Completely nothing to do.  Return FALSE.
        if ($ip == null and $email == null and $username == null) return FALSE;

        if ($border === null or $border < 0) $border = $this->getConf('freqBorder');
        if ($border == 0 and $returnvalue == FALSE) return FALSE;
        if ($this->whitelists and $returnvalue == FALSE) return FALSE;

        // Get the data from the function "rawdata" above.
        $resultarray = $this->rawdata($ip, $email, $username);

        if (isset($resultarray['ip']['frequency'])) $ipfreq = $resultarray['ip']['frequency']; else $ipfreq = -1;
        if (isset($resultarray['email']['frequency'])) $emailfreq = $resultarray['email']['frequency']; else $emailfreq = -1;
        if (isset($resultarray['username']['frequency'])) $namefreq = $resultarray['username']['frequency']; else $namefreq = -1;
        if (isset($resultarray['ip']['confidence'])) $ipconf = $resultarray['ip']['confidence']; else $ipconf = -1;
        if (isset($resultarray['email']['confidence'])) $emailconf = $resultarray['email']['confidence']; else $emailconf = -1;
        if (isset($resultarray['username']['confidence'])) $nameconf = $resultarray['username']['confidence']; else $nameconf = -1;

        if ($returnvalue) return array('ip' => $ipfreq, 'email' => $emailfreq, 'username' => $namefreq);

        if ($ipfreq >= $border or $emailfreq >= $border or $namefreq >= $border) {
            $logfilename = $this->getConf('logPlace');
            if ($logfilename == '') return TRUE;
            if ($loghandle = fopen($logfilename, 'a')) {
                $logcontent = "=== " . date('H:i:s M d, Y') . " - higher frequency score than the border ===\n";
                if ($ip != '') $logcontent .= "IP: " . $ip .", frequency " . $ipfreq . ", confidence " . $ipconf . "\n";
                if ($email != '') $logcontent .= "E-mail Address: " . $email .", frequency " . $emailfreq . ", confidence " . $emailconf . "\n";
                if ($username != '') $logcontent .= "User Name: " . $username .", frequency " . $namefreq . ", confidence " . $nameconf . "\n";
                $logcontent .= "It was accessing " . $INFO['id'] . "\n\n";
                fwrite($loghandle, $logcontent);
                fclose($loghandle);
            }
            return TRUE;
        } else return FALSE;
    }

    /**
     * Look for the confidence score of given IP address, e-mail address, and(or) user name
     *
     * @param string $ip - Do nothing about the IP address if empty
     * @param string $email - Do nothing about the e-mail address if empty
     * @param string $username - Do nothing about the user name if empty
     * @param boolean $returnvalue - If true, this function returns the confidence score itself.  If false, it checks whether or not the score is as large as or higher than $border.  This will be TRUE if one or more of the IP, e-mail, and user name is likely a spammer.
     * @param value $border - The conf "confidenceBorder" will be used if empty or minus value.  If $returnvalue is TRUE, the $border will be no use.  Don't check if 0.
     * @return boolean (if $returnvalue is false) or array (otherwise) - The boolean will be TRUE if the user is regarded as a spammer, or FALSE otherwise.  The array's components will be values with keys "ip", "email", and "username".  If the plugin fail to read the confidence score, the value will be -1.
     */
    function confcheck($ip = null, $email = null, $username = null, $returnvalue = FALSE, $border = null){
        global $INFO;

        // All arguments are empty?  Completely nothing to do.  Return FALSE.
        if ($ip == null and $email == null and $username == null) return FALSE;

        if ($border === null or $border < 0) $border = $this->getConf('confidenceBorder');
        if ($border == 0 and $returnvalue == FALSE) return FALSE;
        if ($this->whitelists and $returnvalue == FALSE) return FALSE;

        // Get the data from the function "rawdata" above.
        $resultarray = $this->rawdata($ip, $email, $username);

        if (isset($resultarray['ip']['confidence'])) $ipconf = $resultarray['ip']['confidence']; else $ipconf = -1;
        if (isset($resultarray['email']['confidence'])) $emailconf = $resultarray['email']['confidence']; else $emailconf = -1;
        if (isset($resultarray['username']['confidence'])) $nameconf = $resultarray['username']['confidence']; else $nameconf = -1;
        if (isset($resultarray['ip']['frequency'])) $ipfreq = $resultarray['ip']['frequency']; else $ipfreq = -1;
        if (isset($resultarray['email']['frequency'])) $emailfreq = $resultarray['email']['frequency']; else $emailfreq = -1;
        if (isset($resultarray['username']['frequency'])) $namefreq = $resultarray['username']['frequency']; else $namefreq = -1;

        if ($returnvalue) return array('ip' => $ipconf, 'email' => $emailconf, 'username' => $nameconf);

        if ($ipconf >= $border or $emailconf >= $border or $nameconf >= $border) {
            $logfilename = $this->getConf('logPlace');
            if ($logfilename == '') return TRUE;
            if ($loghandle = fopen($logfilename, 'a')) {
                $logcontent = "=== " . date('H:i:s M d, Y') . " - higher confidence score than the border ===\n";
                if ($ip != '') $logcontent .= "IP: " . $ip .", frequency " . $ipfreq . ", confidence " . $ipconf . "\n";
                if ($email != '') $logcontent .= "E-mail Address: " . $email .", frequency " . $emailfreq . ", confidence " . $emailconf . "\n";
                if ($username != '') $logcontent .= "User Name: " . $username .", frequency " . $namefreq . ", confidence " . $nameconf . "\n";
                $logcontent .= "It was accessing " . $INFO['id'] . "\n\n";
                fwrite($loghandle, $logcontent);
                fclose($loghandle);
            }
            return TRUE;
        } else return FALSE;
    }

    /**
     * Quick check of the IP address
     * Investigates about both the frequency score and the confidence score.
     *
     * @param string $ip - Remote IP address will be used if empty
     * @param value $freqborder - The conf "freqBorder" will be used if empty or minus value.  Don't check if 0.
     * @param value $confborder - The conf "confidenceBorder" will be used if empty or minus value.  Don't check if 0.
     * @return boolean - TRUE if the function freqcheck, confcheck, or both is(are) TRUE, FALSE otherwise.
     */
    function quickipcheck($ip = null, $freqborder = null, $confborder = null){
        if ($ip == '') $ip = $_SERVER['REMOTE_ADDR'];
        $freqcheck = FALSE;
        $confcheck = FALSE;

        $freqcheck = $this->freqcheck($ip, null, null, FALSE, $freqborder);
        $confcheck = $this->confcheck($ip, null, null, FALSE, $confborder);
        if ($freqcheck or $confcheck) return TRUE; else return FALSE;
    }

    /**
     * Report and add a spammer to the database of the forum
     * The API key in configuration "reportAPI" will be automatically used.
     *
     * @param string $ip - Required
     * @param string $email - Required
     * @param string $username - Required
     * @param string $evidence - Optional
     * @return array ('succeeded' => [TRUE if succeeded, or FALSE if failed], 'message' => [a message that indicates whether or not the plugin successfully reported the user (If failed, it contains the error message (sometimes sent by the API).)])
     */
    function addToDatabase($ip = null, $email = null, $username = null, $evidence = null){
        if ($ip == null or $email == null or $username == null) return array('succeeded' => FALSE, 'message' => $this->getLang('lackingArgs'));
        $api = $this->getConf('reportAPI');
        if ($api == '') return array('succeeded' => FALSE, 'message' => $this->getLang('lackingAPI'));

        // The script below was adopted from https://www.stopforumspam.com/usage
        $data = array(
            'username' => $username,
            'ip_addr' => $ip,
            'evidence' => $evidence,
            'email' => $email,
            'api_key' => $api
        );

        $data = http_build_query($data, '', '&', PHP_QUERY_RFC3986);

        $this->ch = curl_init();
        if ($this->ch) {
            curl_setopt ($this->ch, CURLOPT_URL, 'https://www.stopforumspam.com/add.php');
            curl_setopt ($this->ch, CURLOPT_POST, 1);
            curl_setopt ($this->ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt ($this->ch, CURLOPT_RETURNTRANSFER, true);
            $result = curl_exec ($this->ch);
            $detail = curl_getinfo($this->ch);
            curl_close ($this->ch);

            if ($detail['http_code'] == '200') return array('succeeded' => TRUE, 'message' => $this->getLang('submitted')); else return array('succeeded' => FALSE, 'message' => $this->getLang('errorHappened') . strip_tags($result));

        } else return array('succeeded' => FALSE, 'message' => $this->getLang('curlError'));
    }

    /**
     * Check about whitelists in the configuration
     *
     * @param string $ip
     * @param string $email
     * @param string $username
     * @return boolean - TRUE if he is in the whitelist(s), FALSE otherwise
     */
    function whitelists ($ip = null, $email = null, $username = null) {
            global $INFO;

            // IPs
            $exlist = str_replace(array("\r\n", "\r", "\n"), "\n", $this->getConf('ipWhitelist'));
            $exlist = preg_quote($exlist, '/');
            $exlist = str_replace('\*', '[0-9]+', $exlist);
            $exlist = str_replace('\?', '[0-9]', $exlist);
            $exlist = explode("\n", $exlist);

            foreach ($exlist as $checking) {
                if ($checking == '') continue;
                $prefix = '/^' . $checking . '$/';
                if (preg_match($prefix, $ip)) return TRUE;
            }

            // User names
            $exlist = str_replace(array("\r\n", "\r", "\n"), "\n", $this->getConf('nameWhitelist'));
            $exlist = preg_quote($exlist, '/');
            $exlist = str_replace('\*', '.+', $exlist);
            $exlist = str_replace('\?', '.', $exlist);
            $exlist = str_replace('~', '[0-9]+', $exlist);
            $exlist = str_replace('\!', '[0-9]', $exlist);
            $exlist = explode("\n", $exlist);

            foreach ($exlist as $checking) {
                if ($checking == '') continue;
                $prefix = '/^' . $checking . '$/';
                if (preg_match($prefix, $username)) return TRUE;
            }

            // E-mail addresses
            $exlist = str_replace(array("\r\n", "\r", "\n"), "\n", $this->getConf('emailWhitelist'));
            $exlist = preg_quote($exlist, '/');
            $exlist = str_replace('\*', '.+', $exlist);
            $exlist = str_replace('\?', '.', $exlist);
            $exlist = str_replace('~', '[0-9]+', $exlist);
            $exlist = str_replace('\!', '[0-9]', $exlist);
            $exlist = explode("\n", $exlist);

            // IDN conversion
            $emexp = explode('@', $email, 2);
            $ascii = idn_to_ascii($emexp[1]);
            $utf8 = idn_to_utf8($emexp[1]);
            $ascii = $emexp[0] . $ascii;
            $utf8 = $emexp[0] . $utf8;

            foreach ($exlist as $checking) {
                if ($checking == '') continue;
                $prefix = '/^' . $checking . '$/';
                if (preg_match($prefix, $ascii)) return TRUE;
                if (preg_match($prefix, $utf8)) return TRUE;
            }

            // Skip logged-in users, managers and superusers?
            if ($this->getConf('skipMgAndSp') == 'mg' && auth_ismanager()) return TRUE;
            if ($this->getConf('skipMgAndSp') == 'sp' && auth_isadmin()) return TRUE;
            if ($this->getConf('skipMgAndSp') == 'user' && $_SERVER['REMOTE_USER']) return TRUE;

            // Check about a list of users and user groups
            if(auth_isMember($this->getConf('userWhitelist'), $_SERVER['REMOTE_USER'], (array) $USERINFO['grps'])) return TRUE;

            // Not in whitelists
            return FALSE;
    }
}
