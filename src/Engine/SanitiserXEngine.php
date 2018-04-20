<?php
/**
 * SanitiserX
 *
 * Zend 2/3 Module that sanitises requests and inputs against XSS, SQL Injection and more
 *
 * @link https://github.com/Mecanik/SanitiserX
 * @copyright Copyright (c) 2018 Norbert Boros ( a.k.a Mecanik )
 * @license https://github.com/Mecanik/SanitiserX/blob/master/LICENSE
 */

namespace Mecanik\SanitiserX\Engine;

class SanitiserXEngine
{
    /**
     * Function found on google/stackoverflow
     * 
     * Strips out all unwanted javascript tags
     * 
     * @return $data
     */
    static public function sanitize_xss($data)
    {        
        // Fix &entity\n;
        $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
        $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
        $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
        //$data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');
        
        // Remove any attribute starting with "on" or xmlns
        $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);
        
        // Remove javascript: and vbscript: protocols
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);
        
        // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);
        
        // Remove namespaced elements (we do not need them)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);
        
        do
        {
            // Remove really unwanted tags
            $old_data = $data;
            $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
        }
        while ($old_data !== $data);
        
        // we are done...
        return $data;
    }
    
    /**
     * Function found somewhere (can't remmeber where), and slightly edited
     * 
     * @param int $matches
     * @return string
     */
    static public function htmlspecialchars_unicode_callback($matches)
    {
        if (count($matches) == 1)
        {
            return '&amp;';
        }
        
        if (strpos($matches[2], '#') === false)
        {
            // &gt; like
            if ($matches[2] == 'shy')
            {
                return '&shy;';
            }
            else
            {
                return "&amp;$matches[2];";
            }
        }
        else
        {
            // Only convert chars that are in ISO-8859-1
            if (($matches[3] >= 32 AND $matches[3] <= 126)
                OR
                ($matches[3] >= 160 AND $matches[3] <= 255))
            {
                return "&amp;#$matches[3];";
            }
            else
            {
                return "&#$matches[3];";
            }
        }
    }
    
    /**
     * Function found somewhere (can't remmeber where), and slightly edited
     * 
     * @param string $text
     * @param boolean $entities
     * @return mixed
     */
    static public function htmlspecialchars_unicode($text, $entities = true)
    {
        
        if ($entities)
        {
            $text = preg_replace_callback(
                '/&((#([0-9]+)|[a-z]+);)?/si', array(get_called_class(), 'htmlspecialchars_unicode_callback') ,$text);
        }
        else
        {
            $text = preg_replace(
                // translates all non-unicode entities
                '/&(?!(#[0-9]+|[a-z]+);)/si',
                '&amp;',
                $text
                );
        }
        
        return str_replace(
            // replace special html characters
            array('<', '>', '"'),
            array('&lt;', '&gt;', '&quot;'),
            $text
            );
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitise_sql($str){
        
        if (! isset($str) ) {
            return null;
        }else if (is_string($str) ) {
            if (get_magic_quotes_gpc() ) {
                $str = stripslashes($str);
            }
            
            $str2 = str_replace(array('\\', "'", '"', "\x0d", "\x0a", "\x00", "\x1a", '`', '<', '>'),
                array('\\\\', "\\'", '\\"', 'X', 'X', 'X', 'X', '\\`', '\\<', '\\>'),	$str);
            
            return $str2;
            
        }else if (is_array($str) ) {
            foreach($str as $key => $value) {
                if (get_magic_quotes_gpc() ) {
                    $key = stripslashes($key);
                }
                
                $key2 = str_replace(	array('\\', "'", '"', "\x0d", "\x0a", "\x00", "\x1a", '`', '<', '>'),
                    array('\\\\', "\\'", '\\"', 'X', 'X', 'X', 'X', '&#96;', '&lt;', '&gt;'),	$key, $occ);
                if ($occ) {
                    unset($str[$key]);
                }
                
                $str[$key2] = SanitiserXEngine::sanitise_sql($value);
            }
            return $str;
        }
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_unset_globals() {
        if ( ini_get('register_globals') ) {
            $allow = array('_ENV' => 1, '_GET' => 1, '_POST' => 1, '_COOKIE' => 1, '_FILES' => 1, '_SERVER' => 1, '_REQUEST' => 1, 'GLOBALS' => 1);
            foreach ($GLOBALS as $key => $value) {
                if ( ! isset( $allow[$key] ) ) unset( $GLOBALS[$key] );
            }
        }
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_get_env($st_var) {
        global $HTTP_SERVER_VARS;
        if(isset($_SERVER[$st_var])) {
            return strip_tags( $_SERVER[$st_var] );
        } elseif(isset($_ENV[$st_var])) {
            return strip_tags( $_ENV[$st_var] );
        } elseif(isset($HTTP_SERVER_VARS[$st_var])) {
            return strip_tags( $HTTP_SERVER_VARS[$st_var] );
        } elseif(getenv($st_var)) {
            return strip_tags( getenv($st_var) );
        } elseif(function_exists('apache_getenv') && apache_getenv($st_var, true)) {
            return strip_tags( apache_getenv($st_var, true) );
        }
        return '';
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_get_referer() {
        if( self::sanitiserx_get_env('HTTP_REFERER') )
            return self::sanitiserx_get_env('HTTP_REFERER');
            return 'no referer';
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_get_ip() {
        if ( self::sanitiserx_get_env('HTTP_X_FORWARDED_FOR') ) {
            return self::sanitiserx_get_env('HTTP_X_FORWARDED_FOR');
        } elseif ( self::sanitiserx_get_env('HTTP_CLIENT_IP') ) {
            return self::sanitiserx_get_env('HTTP_CLIENT_IP');
        } else {
            return self::sanitiserx_get_env('REMOTE_ADDR');
        }
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_get_user_agent() {
        if(self::sanitiserx_get_env('HTTP_USER_AGENT'))
            return self::sanitiserx_get_env('HTTP_USER_AGENT');
            return 'none';
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_get_query_string() {
        if( self::sanitiserx_get_env('QUERY_STRING') )
            return str_replace('%09', '%20', self::sanitiserx_get_env('QUERY_STRING'));
            return '';
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_get_request_method() {
        if(self::sanitiserx_get_env('REQUEST_METHOD'))
            return self::sanitiserx_get_env('REQUEST_METHOD');
            return 'none';
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function sanitiserx_gethostbyaddr() {
        if ( @ empty( $_SESSION['sanitiserx_gethostbyaddr'] ) ) {
            return $_SESSION['sanitiserx_gethostbyaddr'] = @gethostbyaddr( self::sanitiserx_get_ip() );
            } else {
                return strip_tags( $_SESSION['sanitiserx_gethostbyaddr'] );
            }
    }
    
    /**
     * https://secure.php.net/random_bytes
     * @param number $length
     * @return string
     */
    static public function RandomToken($length = 16){
        if(!isset($length) || intval($length) <= 8 ){
            $length = 32;
        }
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length));
        }
        if (function_exists('mcrypt_create_iv')) {
            return bin2hex(mcrypt_create_iv($length, MCRYPT_DEV_URANDOM));
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            return bin2hex(openssl_random_pseudo_bytes($length));
        }
    }
    
    /**
     * Function taken from an older project of mine ( 2-3 years ago )
     */
    static public function block() 
    {
        return  '<html><head><title>403 Forbidden</title>
				<style>.smallblack{font-family:Verdana,Arial,Helvetica,Ubuntu,"Bitstream Vera Sans",sans-serif;font-size:12px;line-height:16px;color:#000000;}.tinygrey{font-family:Verdana,Arial,Helvetica,Ubuntu, "Bitstream Vera Sans",sans-serif;font-size:10px;line-height:12px;color:#999999;}</style>
				</head><body><br><br><br><br><br>
				<table align=center style="border:1px solid red" cellspacing=0 cellpadding=6 class=smallblack>
				<tr><td align=center><img src="data:image/png;base64,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
" />
					<p>Sorry <b>'.\Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_ip().'</b>, your request cannot be proceeded.<br>For security reasons it was blocked and logged.
				<p>If you think that this was a mistake, please contact<br>the webmaster.</td></tr></table>
				<br><center class=tinygrey>Copyright &copy; '. date('Y') .' SanitizerX</center></body></html>';
    }
}

