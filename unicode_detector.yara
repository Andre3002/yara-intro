/* 
This rule checks if text has unicode characters
To run on all files in a folder (MSI):  
yara64 unicode_detector.yara "C:\Users\andre\Repos\yara-intro\Emails\"
*/

rule DetectUnicode
{
    meta:
        description = "Detects Unicode characters"
    strings:
        $unicode_regex = /[^\x00-\x7F]/
    condition:
        $unicode_regex
}