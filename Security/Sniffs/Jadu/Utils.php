<?php

namespace PHPCS_SecurityAudit\Security\Sniffs\Jadu;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;
use PHPCS_SecurityAudit\Security\Sniffs\Utils as BaseUtils;

class Utils extends BaseUtils
{
    /**
    * Array of XSS mitigation function
    * Note: does not inherit from parent, see is_XSS_mitigation()
    *
    * @return array(String) returns the array of functions
    */
    public static function getXSSMitigationFunctions() {
        return ['encodeHtml', 'encodeHTML', 'intval'];
    }

    /**
    * Verify that a function is a XSS mitigation
    * By default this function will return TRUE even if a normal PHP mitigation function is used,
    * because it's considered a bad practice to do otherwise; see second param $isparent
    *
    * @param $var   The variable containing the function string
    * @param Boolean    bool set to TRUE if we check for the parent's functions, default FALSE
    * @return Boolean   returns TRUE if it's a XSS mitigation function, FALSE otherwise
    */
    public static function is_XSS_mitigation($var, $isparent=FALSE) {
        if ($isparent && parent::is_XSS_mitigation($var)) {
            return TRUE;
        } else {
            if (in_array($var,  Utils::getXSSMitigationFunctions())) {
                return TRUE;
            }
        }
        return FALSE;
    }
}
