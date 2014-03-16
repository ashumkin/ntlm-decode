#!/usr/bin/env perl

use MIME::Base64;

#
# example Outlook 2010 AUTH NTLM strings and decoding
# pi -at- opsec.eu, Mon Nov  1 17:18:26 CET 2010
# format decoded according to
# http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf
# and
# http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf
#

$inp=$ARGV[0];

$res = decode_base64($inp);

$sig = substr($res,0,7);
# has to be NTLMSSP\0

if ( $sig ne 'NTLMSSP' ) {
    print "sig bad: '$sig'\n";
}
else {
    print "sig good: '$sig'\n";
}

@msgtype = split(//,substr($res,8,4));
if ( ord($msgtype[0]) >= 1 && ord($msgtype[0]) < 4 ) {
    print "msgtype good: ";
    if ( ord($msgtype[0]) == 1 ) {
	print "NEGOTIATE ";
	$type = 1;
    }
    elsif ( ord($msgtype[0]) == 2 ) {
	print "CHALLENGE ";
	$type = 2;
    }
    elsif ( ord($msgtype[0]) == 3 ) {
	print "AUTHENTICATE ";
	$type = 3;
    }
}
else {
    print "msgtype bad: ";
}
foreach $c ( @msgtype ) {
    print ord($c).' ';
}
print "\n";

@msg = split(//,substr($res,12,12));
if ( $type == 1 ) {
    print "negflags: ";
    foreach $i ( 0..3 ) {
	print ord($msg[$i]).' ';
    }
    print "\n";
    $bits = unpack("b32",substr($res,12,4));
    print "bits: $bits\n";

    if ( substr($bits,0,1) eq '1' ) {
	print "\tNEGOTIATE_56\n";
    }
    if ( substr($bits,1,1) eq '1' ) {
	print "\tNEGOTIATE_KEY_EXCH\n";
    }
    if ( substr($bits,2,1) eq '1' ) {
	print "\tNEGOTIATE_128\n";
    }
    if ( substr($bits,3,1) eq '1' ) {
	print "\terror: r1-should-be-0\n";
    }
    if ( substr($bits,4,1) eq '1' ) {
	print "\terror: r2-should-be-0\n";
    }
    if ( substr($bits,5,1) eq '1' ) {
	print "\terror: r3-should-be-0\n";
    }
    if ( substr($bits,6,1) eq '1' ) {
	print "\tNEGOTIATE_VERSION\n";
    }
    if ( substr($bits,7,1) eq '1' ) {
	print "\terror: r4-should-be-0\n";
    }
    if ( substr($bits,8,1) eq '1' ) {
	print "\tNEGOTIATE_TARGET_INFO\n";
    }
    if ( substr($bits,9,1) eq '1' ) {
	print "\tREQUEST_NON_NT_SESSION_KEY\n";
    }
    if ( substr($bits,10,1) eq '1' ) {
	print "\terror: r5-should-be-0\n";
    }
    if ( substr($bits,11,1) eq '1' ) {
	print "\tNEGOTIATE_IDENTITY\n";
    }
    if ( substr($bits,12,1) eq '1' ) {
	print "\tNEGOTIATE_EXTENDED_SESSIONSECURITY\n";
    }
    if ( substr($bits,13,1) eq '1' ) {
	print "\terror: r6-should-be-0\n";
    }
    if ( substr($bits,14,1) eq '1' ) {
	print "\tTARGET_TYPE_SERVER\n";
    }
    if ( substr($bits,15,1) eq '1' ) {
	print "\tTARGET_TYPE_DOMAIN\n";
    }
    if ( substr($bits,16,1) eq '1' ) {
	print "\tNEGOTIATE_ALWAYS_SIGN\n";
    }
    if ( substr($bits,17,1) eq '1' ) {
	print "\terror: r7-should-be-0\n";
    }
    if ( substr($bits,18,1) eq '1' ) {
	print "\tNEGOTIATE_OEM_WORKSTATION_SUPPLIED\n";
    }
    if ( substr($bits,19,1) eq '1' ) {
	print "\tNEGOTIATE_OEM_DOMAIN_SUPPLIED\n";
    }
    if ( substr($bits,20,1) eq '1' ) {
	print "\tconnection should be anonumous\n";
    }
    if ( substr($bits,21,1) eq '1' ) {
	print "\terror: r8-should-be-0\n";
    }
    if ( substr($bits,22,1) eq '1' ) {
	print "\tNEGOTIATE_NTLM\n";
    }
    if ( substr($bits,23,1) eq '1' ) {
	print "\terror: r9-should-be-0\n";
    }
    if ( substr($bits,24,1) eq '1' ) {
	print "\tNEGOTIATE_LM_KEY\n";
    }
    if ( substr($bits,25,1) eq '1' ) {
	print "\tNEGOTIATE_DATAGRAM\n";
    }
    if ( substr($bits,26,1) eq '1' ) {
	print "\tNEGOTIATE_SEAL\n";
    }
    if ( substr($bits,27,1) eq '1' ) {
	print "\tNEGOTIATE_SIGN\n";
    }
    if ( substr($bits,28,1) eq '1' ) {
	print "\terror: r10-should-be-0\n";
    }
    if ( substr($bits,29,1) eq '1' ) {
	print "\tREQUEST_TARGET\n";
    }
    if ( substr($bits,30,1) eq '1' ) {
	print "\tNEGOTIATE_OEM\n";
    }
    if ( substr($bits,31,1) eq '1' ) {
	print "\tNEGOTIATE_UNICODE\n";
    }

    print "DomainNameFields: ";
    foreach $i ( 4..11 ) {
	print ord($msg[$i]).' ';
    }
    print "\n";
}
elsif ( $type == 2 ) {
    $len = length($res);
    print "length: $len\n";

    print "TargetNameFields: ";
    @t = split(//,substr($res,12,8));
    foreach $i ( 0..7 ) {
	print ord($t[$i]).' ';
    }
    print "\n";

    print "NegotiateFlags: ";
    @t = split(//,substr($res,20,4));
    foreach $i ( 0..3 ) {
	print ord($t[$i]).' ';
    }
    print "\n";

    print "ServerChallenge: ";
    @t = split(//,substr($res,24,8));
    foreach $i ( 0..7 ) {
	print ord($t[$i]).' ';
    }
    print "\n";

    print "Reserved: ";
    @t = split(//,substr($res,32,8));
    foreach $i ( 0..7 ) {
	print ord($t[$i]).' ';
    }
    print "\n";

    print "TargetInfoFields: ";
    @t = split(//,substr($res,40,8));
    foreach $i ( 0..7 ) {
	print ord($t[$i]).' ';
    }
    print "\n";

    print "Version: ";
    @t = split(//,substr($res,48,8));
    foreach $i ( 0..7 ) {
	print ord($t[$i]).' ';
    }
    print "\n";

}

