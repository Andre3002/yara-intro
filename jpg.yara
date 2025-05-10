/* 
This rule checks the file signature to see if a file is a jpg
To run on all files in a folder:  yara64 jpg.yara "C:\Users\andre\Yara_Rules\Emails\TestPic.jpg"
*/

rule jpg_file_found
{
meta:
    description = "Determine if file is a .jpg"
strings:
    $s1 = {ff d8}
condition:
    $s1 at 0
}

    