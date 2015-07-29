#!/usr/bin/perl -w
# by M. Trojnara 1998 for stunnel only

use strict;

my $txt="";
while(<>) {
    $txt.=$_;
}
$_=$txt;
s/</&lt;/g;
s/>/&gt;/g;

s/^\.B (.*)/<B>$1<\/B>/gm;
s/^\.BI (.*)/<I><B>$1<\/I><\/B>/gm;
s/^\.BR (.*)/<FONT FACE="Roman"><B>$1<\/FONT><\/B>/gm;

s/^\.RS/<BLOCKQUOTE>\n/gm;
s/^\.RE/<\/BLOCKQUOTE>\n/gm;

s/^\.TH\s+(\S+)\s+(\S+).*/<H1>$1($2)<\/H1>/gm;
s/^\.nf/<PRE>\n/gm;
s/^\.fi/<\/PRE>\n/gm;
s/^\.SH *(.*)/<DD><BR><DT><B>$1<\/B><DD>/gm;

s/^\.TP/<DD>\n/gm;
s/^\.br/<DD>\n/gm;
s/^\.PP/<DD>\n/gm;

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

