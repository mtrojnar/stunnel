#!/usr/bin/perl

$config   = "/tmp/ssl/openssl.cnf";
$capath   = "/usr/local/ssl/bin/openssl ca";
$certpass = "adas";
$tempca   = "/tmp/ssl/cli".rand 10000;
$tempout  = "/tmp/ssl/certtmp".rand 10000;
$caout    = "/tmp/ssl/certwynik.txt";
$CAcert   = "/tmp/ssl/demoCA/cacert.pem";
$spkac	  = "";




&ReadForm;

$spkac = $FIELDS{'SPKAC'};
$spkac =~ s/\n//g;

open(TEMPCE,">$tempca") || die &Error;
print TEMPCE "C = $FIELDS{'country'}\n";
print TEMPCE "ST = $FIELDS{'state'}\n";
print TEMPCE "O = $FIELDS{'organization'}\n";
print TEMPCE "Email = $FIELDS{'email'}\n";
print TEMPCE "CN = $FIELDS{'who'}\n";
print TEMPCE "SPKAC = $spkac\n";
close(TEMPCE);                         

system("$capath -batch -config $config -spkac $tempca -out $tempout -key $certpass -cert $CAcert>> $caout 2>&1"); 
open(CERT,"$tempout") || die &Error;
@certyfikat = <CERT>;
close(CERT);

#system("rm -f $tempca");
#system("rm -f $tempout");

print "Content-type: application/x-x509-user-cert\n\n";
print @certyfikat;





##############################################################
####
####     Procedury 
####


sub ReadForm {

   if ($ENV{'REQUEST_METHOD'} eq 'GET') {
      @pairs = split(/&/, $ENV{'QUERY_STRING'});
   }
   elsif ($ENV{'REQUEST_METHOD'} eq 'POST') {
      read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});

      @pairs = split(/&/, $buffer);
   }
  
   foreach $pair (@pairs) {
      ($name, $value) = split(/=/, $pair);

      $name =~ tr/+/ /;
      $name =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

      $value =~ tr/+/ /;
      $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

      $value =~ s/<!--(.|\n)*-->//g;

      $FIELDS{$name} = $value;
      
      }
 
}

sub Error {

    print "Content-type: text/html\n\n";
    print "<P><P><center><H1>Cant open file</H1></center>\n";

}