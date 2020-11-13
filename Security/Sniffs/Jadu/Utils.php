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
        return [
            // Jadu CMS functions
            'encodeHtml',
            'buildAccessibilityURL',
            'buildAToZURL',
            'buildAToZIndexURL',
            'buildChangeDetailsURL',
            'buildNonReadableChangeDetailsURL',
            'buildChangePasswordURL',
            'buildNonReadableChangePasswordURL',
            'buildContactURL',
            'buildCouncillorsURL',
            'buildCouncillorsIndividualURL',
            'buildCouncillorsGroupURL',
            'buildDocumentsIndexURL',
            'buildDocumentsURL',
            'buildNonReadableDocumentsURL',
            'buildDocumentsCategoryURL',
            'buildDownloadsURL',
            'buildNonReadableDownloadsURL',
            'buildEmailFriendURL',
            'buildNonReadableEmailFriendURL',
            'buildEventsURL',
            'buildNonReadableEventsURL',
            'buildNewEventURL',
            'buildNonReadableNewEventURL',
            'buildFAQURL',
            'buildNonReadableFAQURL',
            'buildIndividualFAQURL',
            'buildFeedbackURL',
            'buildNonReadableFeedbackURL',
            'buildForgotPasswordURL',
            'buildNonReadableForgotPasswordURL',
            'buildFormsCategoryURL',
            'buildHomeURL',
            'buildNonReadableHomeURL',
            'buildLinksURL',
            'buildLocationURL',
            'buildMeetingsURL',
            'buildMeetingsArchiveURL',
            'buildNewsURL',
            'buildPressURL',
            'buildNewsArchiveURL',
            'buildPressArchiveURL',
            'buildNewsArticleURL',
            'buildNonReadableNewsArticleURL',
            'buildPressArticleURL',
            'buildPageCommentsURL',
            'buildNonReadablePageCommentsURL',
            'buildPollResultsURL',
            'buildNonReadablePollResultsURL',
            'buildPastPollResultsURL',
            'buildRegisterAcceptURL',
            'buildRegisterURL',
            'buildNonReadableRegisterURL',
            'buildRegisterAuthURL',
            'buildAboutURL',
            'buildAboutRSSURL',
            'buildCategoryRSSURL',
            'buildAboutPodcastRSSURL',
            'buildRSSURL',
            'buildSearchURL',
            'buildSearchResultsURL',
            'buildNonReadableSearchResultsURL',
            'buildAZServiceURL',
            'buildAZServicePIDURL',
            'buildAZServicesCategoryURL',
            'buildAccountSigninURL',
            'buildSiteMapURL',
            'buildTermsURL',
            'buildEventThanksURL',
            'buildThanksURL',
            'buildUnsubscribeURL',
            'buildNonReadableUnsubscribeURL',
            'buildUserSettingsURL',
            'buildNonReadableUserSettingsURL',
            'buildUserFormURL',
            'buildUserHomeURL',
            'buildNonReadableUserHomeURL',
            'buildStatisticsURL',
            'buildFeedsURL',
            'buildWhatsNewURL',
            'buildCouncillorLookupURL',
            'buildXFormsURL',
            'buildNonReadableXFormsURL',
            'buildSignOutURL',
            'buildSignInURL',
            'buildNonReadableSignInURL',
            'buildMultimediaGalleriesURL',
            'buildMultimediaPodcastsURL',
            'buildDirectoriesURL',
            'buildNonReadableDirectoriesURL',
            'buildDirectoryAZURL',
            'buildDirectoryRecordURL',
            'buildNonReadableDirectoryRecordURL',
            'buildDirectorySearchURL',
            'buildDirectoryCategoryURL',
            'buildAPIApplyURL',
            'buildNonReadableAPIApplyURL',
            'buildAPIKeyURL',
            'buildBlogURL',
            'buildCookiesErrorURL',
            'buildJobsURL',
            'buildJobApplicationURL',
            'getStaticContentRootURL',
            'getSecureStaticContentRootURL',
            'getSiteRootURL',
            'getSecureSiteRootURL',
            'getCurrentProtocolSiteRootURL',

            // Jadu XFP functions
            'buildXFormsProFormURL',
            'buildXFormsProStreamPDFFormURL',
            'buildXFormsProStreamPDFUserFormURL',
            'buildXFormsProUserFormURL',
            'buildXFormsProEPaymentIntegrationURL',
            'buildXFormsProCategoryURL',
            'buildXFormsProCategoryRSSURL',
            'buildNonReadableXFPUserHomeURL',

            // Safe formats
            'intval',
            '(int)',

            // Other
            '.', // Reporting concatenation on print is overly cautious.
        ];
    }

    /**
    * Verify that a function is a XSS mitigation
    * By default this function will return TRUE even if a normal PHP mitigation function is used,
    * because it's considered a bad practice to do otherwise; see second param $isparent
    *
    * @param $var       The variable containing the function string
    * @param Boolean    bool set to TRUE if we check for the parent's functions, default FALSE
    * @return Boolean   returns TRUE if it's a XSS mitigation function, FALSE otherwise
    */
    public static function is_XSS_mitigation($var, $isparent=FALSE) {
        if ($isparent && parent::is_XSS_mitigation($var)) {
            return TRUE;
        } else {
            $xssMitigationFunctions = array_map('strtolower', Utils::getXSSMitigationFunctions());
            if (in_array(strtolower($var),  $xssMitigationFunctions)) {
                return TRUE;
            }
        }
        return FALSE;
    }
}
