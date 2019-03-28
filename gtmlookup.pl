#!/usr/bin/perl
# gtmlookup.pl
# j.willis@f5.com - 4/21/2015
#
# Objectives:
# 1. Perform queries against GTM listeners and compare responses pre and post change
# 	- if responses are single round-robin answers, answers will be compared 
# 	against acceptable list of member IPs for that WIP from GTM config. IPs that do not
# 	match the list of acceptable IPs will be labeled "bad" and returned for comparison.
# 	- if responses are multiple round-robin answers, all answers will be returned
# 	for comparison. 
# 	- if method used is not round-robin (ie. ratio, hashed, or GA), answers will be
# 	returned for comparison.
# 	- failed responses will be returned for comparison.
# 	
# Usage: ./gtmlookup.pl <GTM-config file> <GTM-config file> <name server> <verboseLvl 1=verbose 2=debug>
# 	GTM-config file: the GTM config
# 	Name Server: the name server to query
# 	Verbosity Level: none=normal 1=verbose 2=debug
# 	Example: ./gtmlookup.pl GTM-config.cfg 10.10.100.252 2
#

use strict;
use warnings;


my ($confFile, $confFD, $sleep,$digResult,$retry,$aType,$type,$wideip,$pool, $name, $wipName,$dnsServer,$server,$wipPool,$member,$state,$vs,$poolMember);
my ($poolFound,$wipFound,$serverFound,$vsFound,$wipPoolFound,$memberVS);
my %wips = ();
my %pools = ();
my %vses = ();
my %ips =();
my (@ipRes,@ip);
my $verboseLvl = 0;

if ($#ARGV >= 0) {
    $confFile = $ARGV[0];
    if ($ARGV[1] && $ARGV[1] =~ /\d+\.\d+\.\d+\.\d+|.*\..*\..*/) {
        $dnsServer = $ARGV[1];
        if ($ARGV[2] && $ARGV[2] =~ /\d/) {
            $verboseLvl = $ARGV[2]
        }
    } elsif ($ARGV[1]) {
        $verboseLvl = $ARGV[1];
    }
} else {
    print "Usage: ./gtmlookup.pl <GTM-config file> <name server> <verboseLvl 1=verbose 2=debug>";
    print "\n\tGTM-config file: the GTM config\n\tName Server: the name server to query";
    print "\n\tVerbosity Level: none=normal 1=verbose 2=debug";
    print "\n\nExample: ./gtmlookup.pl GTM-config.cfg 10.10.100.252 2\n";
    exit;
}

&getGTMConfig;
&assembleGTMObjects;

########### Subroutines ##############

sub getGTMConfig {
    # Parse GSS config and store info from domains, dns rules, answer-groups, and answer-adds in hashes
    
    open($confFD, $confFile) || die "Unable to open $confFile: $!\n";
    while (<$confFD>) {
        chomp();
        $_ =~ s/[\r\n]$//;
        $_ =~ s/\s+$//;
        $_ =~ s/\"//g;

        if (/^gtm pool / .. /^}/) {
            if (/^gtm pool (a |aaaa |)(.*) \{/) {
                $type = $1;
                $type = "a" if ($type eq "");
                $pool = $2;
                $type =~ s/\s//;
                $pools{$type}{pools}{$pool}{type} = $type;
                $pools{$type}{pools}{$pool}{name} = $pool;
                $pools{$type}{pools}{$pool}{lbMode} = "round-robin";
                $pools{$type}{pools}{$pool}{maxAddr} = "1";
            }
            if (/ load\-balancing\-mode (.*)/) {
                $pools{$type}{pools}{$pool}{lbMode} = $1;
            }
            if (/ max\-address\-returned (\d+)/) {
                $pools{$type}{pools}{$pool}{maxAddr} = $1;
            }
            if (/\s{8}((.*):(.*)) \{/) {
                $member = $1;
                $server = $2;
                $memberVS = $3;
                $server =~ s/^\s+//;
                $server =~ s/\s+$//;
                $memberVS =~ s/\/Common\///;
                $pools{$type}{pools}{$pool}{members}{$member}{state} = "enabled";
                $pools{$type}{pools}{$pool}{members}{$member}{server} = $server;
                $pools{$type}{pools}{$pool}{members}{$member}{memberVS} = $memberVS;
            }
            if (/^\s+disabled/) {
                $pools{$type}{pools}{$pool}{members}{$member}{state} = "disabled";
            }
            if (/ (?:member-|)order (\d+)/) {
                $pools{$type}{pools}{$pool}{members}{$member}{order} = $1;
            }
        }

        if (/^gtm server / .. /^}/) {
            if (/^gtm server (.*) \{/) {
                $server = $1;
                $server =~ s/^\s+//;
                $server =~ s/\s+$//;
                $vses{$server}{name} = $server;
            }
            if (/datacenter (.*)/) {
                my $datacenter = $1;
                $vses{$server}{datacenter} = $datacenter;
            }
            if (/ virtual\-servers \{/ .. /^}/) {
                if ( /\s+(.*) \{$/ && !(/depends-on/)) {
                    $vs = $1;
                    $vs =~ s/^\s+//;
                    $vs =~ s/\s+$//;
                }
                if (/ destination (\d*\.\d*\.\d*\.\d*):/) {
                    $vses{$server}{vses}{$vs}{ip} = $1;
                    my $ip = $1;
                    $ips{$ip}{ip} = $1;
                    $ips{$ip}{datacenter} = $vses{$server}{datacenter};
                # if no match for ipv4 address, try this to match an ipv6 address
                } elsif (/ destination (.*)\./) {
                    $vses{$server}{vses}{$vs}{ip} = $1;
                    my $ip = $1;
                    $ips{$ip}{ip} = $1;
                    $ips{$ip}{datacenter} = $vses{$server}{datacenter};
                }
            }
        }

        if (/^gtm wideip / .. /^}/) {
            if (/^gtm wideip (a |aaaa |)(.*) \{/) {
                $type = $1;
                $type = "a" if ($type eq "");
                $wideip = $2;
                $type =~ s/\s//;
                $wideip =~ s/\/Common\///;
                $wips{$type}{wips}{$wideip}{name} = $wideip;
                $wips{$type}{wips}{$wideip}{lbMode} = "round-robin";
                @{$wips{$type}{wips}{$wideip}{ips}} = ();
            }
            if (/ pool\-lb\-mode (.*)/) {
                $wips{$type}{wips}{$wideip}{lbMode} = $1;
            }
            if (/ pools \{/ .. /^}/) {
                if ( /\s{8}(.*) \{/ ) {
                    $wipPool = $1;

                }

                if ( / order (\d+)/ ) {
                    $wips{$type}{wips}{$wideip}{pools}{$wipPool}{order} = $1;
                }
            }
        }
    }
}

sub assembleGTMObjects {
    # Retrieve wips, pools, and members stored in hashes
    foreach $type (sort keys %wips){
        $aType = $type;
        foreach $wipName (sort keys %{$wips{$type}{wips}}) {
            $name = $wipName;
            my $printBuffer = "";
            $printBuffer = $printBuffer . "WIP: $wipName  Type: $type\n";
            $printBuffer = $printBuffer . "\tLB-Mode: $wips{$type}{wips}{$wipName}{lbMode}\n";
            foreach $wipPool (sort keys %{$wips{$type}{wips}{$wipName}{pools}}){
                $printBuffer = $printBuffer . "\tPool: $wipPool - LB-Mode: $pools{$type}{pools}{$wipPool}{lbMode} - Order: $wips{$type}{wips}{$wipName}{pools}{$wipPool}{order}\n";
                foreach $poolMember (sort keys %{$pools{$type}{pools}{$wipPool}{members}}){
                    $server = $pools{$type}{pools}{$wipPool}{members}{$poolMember}{server};
                    $memberVS = $pools{$type}{pools}{$wipPool}{members}{$poolMember}{memberVS};
                    next if !($server);
                    chomp($server);
                    $printBuffer = $printBuffer . "\t\t$vses{$server}{datacenter} $server $memberVS $vses{$server}{vses}{$memberVS}{ip} $pools{$type}{pools}{$wipPool}{members}{$poolMember}{state} $pools{$type}{pools}{$wipPool}{members}{$poolMember}{order}\n";

                    next if ( grep( /$vses{$server}{vses}{$memberVS}{ip}/, @{$wips{$type}{wips}{$wipName}{ips}} ) );
                    if ($pools{$type}{pools}{$wipPool}{members}{$poolMember}{state} =~ /enabled/ ) {
                        push (@{$wips{$type}{wips}{$wipName}{ips}}, $vses{$server}{vses}{$memberVS}{ip});
                    } 
                }
                if ($wips{$type}{wips}{$wipName}{pools}{$wipPool}{order} == "0") {
                    $wips{$type}{wips}{$wipName}{mainLBMode} = $pools{$type}{pools}{$wipPool}{lbMode};
                }
            }

            if ( scalar @{$wips{$type}{wips}{$wipName}{ips}} == 0) {
                $printBuffer = $printBuffer . "No Acceptable IPs - no enabled answer IPs\n";
            } elsif ( scalar @{$wips{$type}{wips}{$wipName}{ips}} >= 1 ) {
                $printBuffer = $printBuffer . "Acceptable IPs: @{$wips{$type}{wips}{$wipName}{ips}}\n";
            }

            
            if ($verboseLvl >= 2) {
                print "\n$printBuffer";
            }
            @ipRes = &dig_address($name);
            &showResults(@{$wips{$type}{wips}{$wipName}{ips}});
        }
    }
}

sub dig_address {
    my @digRes =();
    my ($wip) = @_;

    if ($dnsServer) {
        $digResult = `dig $aType $wip\. \@$dnsServer | awk '/;; ANSWER SECTION:/,/\^\$/ {if (\$0 ~ /IN[[:space:]]A/) print \$NF}'`;        
    } else {
        $digResult = `dig $aType $wip\. | awk '/;; ANSWER SECTION:/,/\^\$/ {if (\$0 ~ /IN[[:space:]]A/) print \$NF}'`;
    }

    @digRes = split /\n/, $digResult;
    return(@digRes);
}

sub showResults {
    (@ip) = @_;
    my $datacenter = "undefined";
    if (@ipRes) {
        if ($ips{$ipRes[0]}{datacenter}) {
            $datacenter = $ips{$ipRes[0]}{datacenter}
        }
    }
    if ( scalar @ipRes >= 2) {
        # multiple answer IPs in response
        if ($verboseLvl >= 1) {
            print "$name - $aType - @ipRes - LB Mode: $wips{$aType}{wips}{$name}{mainLBMode} ** MULTIPLE ANSWERS **\n"; 
        } else {
            print "$name - $aType - @ipRes - $wips{$aType}{wips}{$name}{mainLBMode}\n";
        }
        if ($verboseLvl == 1 ) {
            print "Acceptable IPs: @ip\n\n";
        }
    } elsif ( scalar @ipRes == 0) {
        # no answer IPs returned in response
        if ($verboseLvl >= 1 ) {
            print "$name - $aType - FAILED: no-answers-returned\n\n"
        } else {
            print "$name - $aType - FAILED-no-answers-returned\n"
        }
    } else {
        if ($wips{$aType}{wips}{$name}{mainLBMode} !~ /round-robin/ ) {
            # not round-robin method - show answer IP responses
            if (grep {$_ eq $ipRes[0]} @ip){
                if ($verboseLvl >= 1 ) {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - Good Answer - LB Mode: $wips{$aType}{wips}{$name}{mainLBMode} ** NOT ROUND-ROBIN **\n";                    
                } else {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - Good-answer - $wips{$aType}{wips}{$name}{mainLBMode}\n";
                }
            } else {
                if ($verboseLvl >= 1 ) {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - LB Mode: $wips{$aType}{wips}{$name}{mainLBMode} ** NOT ROUND-ROBIN **\n";
                } else {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - BAD-ANSWER - $wips{$aType}{wips}{$name}{mainLBMode}\n";
                }
            }
            if ($verboseLvl == 1 ) {
                print "Acceptable IPs: @ip\n\n";
            }
        } else {
            # method is round-robin - check if response is an acceptable IP
            if (grep {$_ eq $ipRes[0]} @ip){
                if ($verboseLvl >= 1 ) {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - Good Answer - LB Mode: $wips{$aType}{wips}{$name}{mainLBMode} ** ROUND-ROBIN RESPONSE **\n";                    
                } else {
                    print "$name - $aType - Datacenter: $datacenter - Good-answer - $wips{$aType}{wips}{$name}{mainLBMode}\n";                    
                }
            } else {
                if ($verboseLvl >= 1 ) {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - ** BAD ANSWER **\n";                    
                } else {
                    print "$name - $aType - Datacenter: $datacenter - Answer: @ipRes - BAD-ANSWER\n";             
                }
            }
            if ($verboseLvl == 1 ) {
                print "Acceptable IPs: @ip\n\n";
            }
        }
    }
}


