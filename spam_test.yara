/*
Determines if email contains keywords associated with spam with passing email authentication
To run on all files in a folder (MSI):  
yara64 spam_test.yara "C:\Users\andre\Repos\yara-intro\Emails\"
*/

rule spam_test
{
meta:
    description = "Test if an email is spam"

strings:
    $terms1 = /free*/ //simple regex
    $terms2 = "100% guarantee" nocase
    $terms3 = "amazing" nocase
    $terms4 = "act now" nocase
    
    $auth1 = "spf=pass" nocase
    $auth2 = "dkim=pass" nocase
    $auth3 = "dmarc=pass" nocase

condition:
    1 of ($terms*) and 2 of ($auth*)
}
