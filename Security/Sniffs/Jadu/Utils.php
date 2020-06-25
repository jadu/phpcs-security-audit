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
        return ['encodeHtml', 'encodeHTML', 'htmlentities', 'htmlspecialchars'];
    }
}
