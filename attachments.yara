/* 
This rule checks if email has an attachment
To run on all files in a folder (MSI):  
yara64 attachments.yara "C:\Users\andre\Repos\yara-intro\Emails\"
*/

rule attachments
{
meta:
    description = "Determine if email has attachments"

strings:
    $attachment = "X-Attachment-Id"
    
condition:
    $attachment
}