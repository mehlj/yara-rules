private rule isPE
{
meta:
    description = "using file magic for PE binary"
    author = "Justen Mehl"
    date = "29 April 2017"
strings:
    $magic = {4D 5A}
condition:
     $magic at 0
}

private rule isPDF
{ 
meta:
    description = "using file magic for PDF"
    author = "Justen Mehl"
    date = "29 April 2017"
strings:
    $magic = {25 50 44 46}
condition:
     $magic at 0
}

private rule isZIP
{
meta:
    description = "using file magic for ZIP"
    author = "Justen Mehl"
    date = "29 April 2017"
strings:
    $magic = {(50 4B 03 04 | 50 4B 07 08)}
condition:
     $magic at 0
}

private rule EML 
{
meta:
	description = "standard EML"
	author = "Justen Mehl"
	date = "29 April 2017"
strings:
	$a = "Received:" 
	$b = "From:"
	$c = "Subject:"
condition:
	all of them	
}

private rule outlook
{
meta:
	description = "outlook email"
	author = "Justen Mehl"
	date = "29 April 2017"
strings:
	$a = {52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79}

condition:
	$a at 512	
}

private rule isJPEG
{
meta:
	description = "using file magic for JPG images"
	author = "Justen Mehl"
	date = "29 April 2017"
strings:
	$magic = {FF D8 FF}
condition:
	$magic at 0
}


