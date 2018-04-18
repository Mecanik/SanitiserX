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
}

