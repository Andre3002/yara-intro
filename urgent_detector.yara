/* 
This rule checks if text has sense of urgency
To run on all files in a folder (MSI):  
yara64 urgent_detector.yara "C:\Users\andre\Repos\yara-intro\Emails\"
*/

rule DetectUrgentEmail
{
    meta:
        description = "Detects urgent requests in email body"               
    strings:
        $urgent1 = /urgent/ nocase
        $urgent2 = /immediate/ nocase
        $request1 = /request/ nocase
        $request2 = /need/ nocase
        $action1 = /action required/ nocase
        $action2 = /respond/ nocase
    condition:
        ($urgent1 or $urgent2) and ($request1 or $request2 or $action1 or $action2)
}