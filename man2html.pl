#!/usr/bin/perl -w
# by M. Trojnara 1998,2000 for stunnel only

# use strict;

my $txt="";
while(<>) {
    $txt.=$_;
}
$_=$txt;
s/</&lt;/g;
s/>/&gt;/g;

# .B Bold With text, sets text in bold. On a line by itself, changes to bold font. 
s/^\.B (.*)/<B>$1<\/B>/gm;

# .BI Bold italic Alternates bold and italic fonts. 
s/^\.BI (.*)/<I><B>$1<\/I><\/B>/gm;

# .BR Bold roman Alternates bold and roman fonts. 
s/^\.BR (.*)/<FONT FACE="Roman"><B>$1<\/FONT><\/B>/gm;

# .DT Defines tabs and sets tab stops The default is 7.2 ens in troff and 5 ens in nroff. 

# .HP Hanging paragraph Begin hanging paragraph. 

# .I Italics With text, sets text in italics. On a line by itself, changes to italic font. 
s/^\.I (.*)/<I>$1<\/I>/gm;

# .IB Italic bold Alternates italic and bold fonts. 
s/^\.IB (.*)/<I><B>$1<\/I><\/B>/gm;

# .IP Indented paragraph Begin Indented paragraph. 

# .IR Italic roman Alternates italic and roman fonts. 
s/^\.IR (.*)/<FONT FACE="Roman"><I>$1<\/FONT><\/I>/gm;

# .LP Block-style paragraph Begin Block-style paragraph. 

# .P Paragraph Synonym for .PP. .P actually calls .PP. 
s/^\.PP/<P>/gm;

# .PD Sets the distance between paragraphs The default is .4v in troff and 1v in nroff. 

# .PM Proprietary marking This is an AT&T macro for placing different types of Proprietary notices at the bottom of each page. 

# .PP Paragraph Begin normal paragraph. 
s/^\.PP/<P>/gm;

# .R Roman With text, sets text in roman type. On a line by itself, changes to roman type. 
s/^\.R (.*)/<FONT FACE="Roman">$1<\/FONT>/gm;

# .RB Roman bold Alternates roman and bold fonts. 
s/^\.RB (.*)/<FONT FACE="Roman"><B>$1<\/FONT><\/B>/gm;

# .RE Relative Indent End Ends a relative indent begun by .RS 
s/^\.RE/<\/BLOCKQUOTE>/gm;

# .RI Roman italic Alternates roman and italic fonts. 
s/^\.RI (.*)/<FONT FACE="Roman"><I>$1<\/FONT><\/I>/gm;

# .RS Begins relative indent Begin indent relative to current. 
s/^\.RS/<BLOCKQUOTE>/gm;

# .SH Subhead .SN NAME is the crucial macro for producing the permuted index 
s/^\.SH *(.*)/<P><DT><H2>$1<\/H2><DD>/gm;

# .SM Reduces point size by 2 points Stands for small. 

# .SS Sub-subhead Heading that is not as important as a subhead 

# .TE Table end Denote the end of a table 

# .TH Title head Specify the title heading 
s/^\.TH\s+(\S+)\s+(\S+).*/<DT><H1>$1($2)<\/H1><DD>/gm;

# .TP Indented paragraph with hanging tag. Begin new paragraph. 
s/^\.TP/<DD>/gm;

# .TS Table start Supposedly, the H argument with the .TH macro
#   for continuing table column heads works with the man macros.
#   It's safer, though, to avoid the issue. 


s/^\.nf/<PRE>/gm;
s/^\.fi/<\/PRE>/gm;
s/^\.br/<P>/gm;

s/^\.sp.*//gm;
s/^\.na.*//gm;
s/^\.ti.*//gm;
s/^\.ta.*//gm;

s/^(\..*)/<SUB><I>$1<\/I><\/SUB>/gm;
s/\\f(.)([^\\]*)\\fR/<$1>$2<\/$1>/g;

s/([\w\.]+@[\w\.]+)/<A HREF="MAILTO:$1">$1<\/A>/g;
s/([\w]+:\/\/[\w\.\/~]+)/<A HREF="$1">$1<\/A>/g;

s/\\(.)/$1/g;
while(s/\n\n\n/\n\n/gs)
  {};
s/<PRE>\n+/<PRE>/gs;
s/\n+<\/PRE>/<\/PRE>/gs;
#tr/\n//s;

print "<HTML>\n";
print "<HEAD><TITLE>Manual page<\/TITLE><\/HEAD>\n";
print "<BODY><DL>\n$_</DL><\/BODY>\n";
print "<\/HTML>\n";

