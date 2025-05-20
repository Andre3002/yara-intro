/* 
Testing private rules 
To run on all files in a folder (MSI):  
yara64 private_rules.yara "C:\Users\andre\Repos\yara-intro\Emails\"
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

rule jpg_file_found
{
meta:
    description = "Determine if file is a .jpg"
strings:
    $s1 = {ff d8}
condition:
    $s1 at 0
}
