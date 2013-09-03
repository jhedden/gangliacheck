#!/usr/bin/perl -w
# gangliacheck.pl
# Version 0.1
# http://code.google.com/p/gangliacheck/
# 
# Gangliacheck is a Nagios plugin that queries Ganglia metric information.
# It's primary function is to consolidate the traditional multiple SNMP 
# host resources checks into one status check.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  Change Log
#  * 2008-04-24   - Added cache flag make caching of gmond dumps optional
#  * 2008-08-13   - Removed the temp files and store ganglia data in memory
#  * 2008-12-23		- Commited version 0.1
#
use strict;
use XML::Parser;
use Getopt::Long;
use Socket;
use Time::HiRes qw( usleep );

use Data::Dumper;

my $verbose=0;
my $cache_timeout=300;
my $use_cache_file=0;

my $current_cluster='';

my $data = undef;
my $host_ip = undef;
my $ganglia_host = undef;
my $ganglia_port = 8651;

my %metrics = (
	'load_one'	=> { 'type' => 'numeric', 'warn' => 15, 'crit' => 30 },
	'load_five'	=> { 'type' => 'numeric', 'warn' => 10, 'crit' => 25 },
	'load_fifteen'	=> { 'type' => 'numeric', 'warn' => 5, 'crit' => 20 },
	'mem_free'	=> { 'type' => 'cmp', 'warn' => 90, 'crit' => 95, 'with' => 'mem_total' },
	'swap_free'	=> { 'type' => 'cmp', 'warn' => 25, 'crit' => 80, 'with' => 'swap_total' },
	'disk_usage_'	=> { 'type' => 'glob', 'warn' => 80, 'crit' => 90 },
);

# Eliminate warning
sub foreach_host_tag($$);
sub foreach_host_tag($$) {
  my ($ar,$call) = @_;
   for(my $i = 1; $i < @{$ar}; $i += 2 ) {
    if($$ar[$i] eq 'CLUSTER') {
      my $attrs=@{$$ar[$i+1]}[0];
      $current_cluster = $$attrs{'NAME'} if defined $$attrs{'NAME'};
    }
    foreach_host_tag($$ar[$i+1],$call) if($$ar[$i] eq 'GRID' or $$ar[$i] eq 'CLUSTER');
    &$call($$ar[$i+1]) if($$ar[$i] eq 'HOST');
  }
}

sub do_cmp($$$\$\$) {
	my ($x,$w,$c,$cntW,$cntC) = @_;
	print "$x,$w,$c\n" if($verbose>0);
	return ++$$cntC if ($x >= $c);
	return ++$$cntW if ($x >= $w);
	return 0;
}

sub bail($$) {
	print $_[1];
	exit $_[0];
}

sub dump_gmond($$) {
	my $gmond_data = '';
	my ($host,$port) = @_;
	my $sock;
	my $proto = getprotobyname('tcp');
	my $iaddr = gethostbyname($host) || bail(3,"Unable to resole host: $host");
	my $sin = sockaddr_in($port,$iaddr);
	socket($sock,PF_INET,SOCK_STREAM,$proto);
	connect($sock,$sin) || bail(2, "Failed to connect socket: $!");
	$gmond_data .= $_ while(<$sock>);
	close($sock);
	return $gmond_data;
}

sub usage() {
	print q#check_ganglia.pl host-ip|H ganglia-collector|G [options]
	-H --host-ip		host ip address
	-G --ganglia-collector	ganglia collector to poll
  -L --links Enable HTML link to ganglia-web
	-p --ganglia-port	ganglia collector port
	-I --ignore		ignore this stat
	-T --threshold		set threshold "check:warn:crit"
	-c --cache		cache results (timeout: # . $cache_timeout . q#)
	-D --dump		dump standard checks and quit
	-v --verbose		verbose
#;
	exit 3;
}

GetOptions('verbose|v+' 	=> \$verbose,
	'host-ip|H=s'		=> sub { $_[1] =~ /^(\d+\.){3}\d+$/ || die "Invalid ip: $_[1]\n"; $host_ip=$_[1]; },
	'ganglia-collector|G=s'	=> sub { $_[1] =~ /^\w[\w\.\-]*\w$/ || die "Invalid host: $_[1]\n"; $ganglia_host=$_[1]; },
	'ganglia-port|p=i'	=> \$ganglia_port,
	'ignore|I=s'		=> sub { $_[1] =~ /^\w+$/ || die "Invalid data: $_[0]=$_[1]\n"; delete $metrics{$_[1]}; },
	'cache|c!'		=> \$use_cache_file,
	'dump|D'		=> sub { foreach my $m (keys(%metrics)) { print "$m: ";
						print "$_:$metrics{$m}{$_}," foreach(keys(%{$metrics{$m}})); print "\n"; }; exit 3; },
	'threshold|T=s'		=> sub { $_[1] =~ /^(\w+)\:([0-9\.]+)\:([0-9\.]+)$/ or die "Invalid threshold: $_[1]\n";
						die "Bad check: $1" unless(defined($metrics{$1}));
						$metrics{$1}{'warn'} = $2; $metrics{$1}{'crit'} = $3; },
);
usage unless(defined($host_ip) and defined($ganglia_host));

print "$host_ip\n" if($verbose>0);
print "$ganglia_host\n" if($verbose>0);

my $parser = new XML::Parser(Style => 'Tree');
my $gcache = "/tmp/nagios-gcollector-$ganglia_host-$ganglia_port";
my $tree;
if ($use_cache_file>0 and -e $gcache and (time - (stat($gcache))[9]) < $cache_timeout) {
	$tree = $parser->parsefile($gcache);
} else {
	my $gmond_data;
	my $nAttempts=3;
	while ( !($gmond_data and $tree = $parser->parse($gmond_data)) ) {
		$gmond_data = dump_gmond($ganglia_host,$ganglia_port);
	}
	bail(2, "Failed to download ganglia data") unless($tree);
	if($use_cache_file>0) {
		open my $fh, ">$gcache" || bail 2,"Failed to update file\n";
		print $fh $gmond_data;
		close($fh);
	}
}

($$tree[0] eq 'GANGLIA_XML') or bail 2, "Invalid xml file: root is " . $$tree[0] . ", expected GANGLIA_XML\n";
foreach_host_tag($$tree[1], sub { 
	my $host = shift;
  my $url = "<a href=\"$$tree[1][4][0]{'AUTHORITY'}?c=$current_cluster&h=$$host[0]{'NAME'}>";
	my $attrs = $$host[0];
	if ($$attrs{'IP'} eq $host_ip) {
		my $crit = 0;
		my $warn = 0;
		my %host_metrics;
    # verify current data
    bail(2, "Stale ganglia data\n") if (time - $$attrs{'REPORTED'} > 900);
    # Verbose: print cluster
    print "Cluster: $current_cluster\n" if ($verbose>0);
    # Collect metric data

		for (my $i=3; $i<@$host;$i++) {
			next unless ($$host[$i] eq 'METRIC');
			$host_metrics{$$host[$i+1][0]{'NAME'}} = $$host[$i+1][0]{'VAL'};
		}
		# Linux never frees cached memory - tweak mem_free
		$host_metrics{mem_free}=$host_metrics{mem_free}+$host_metrics{mem_cached};
		# compare
		foreach my $m (keys %metrics) {
			if ($metrics{$m}{'type'} eq 'numeric') {
				print "$m: $host_metrics{$m}.."
					if(do_cmp($host_metrics{$m},$metrics{$m}{'warn'},$metrics{$m}{'crit'},$warn,$crit)>0);
				print $m . ":" . $host_metrics{$m} . "\n" if($verbose>0);
			} elsif ($metrics{$m}{'type'} eq 'cmp') {
				print "$m: $host_metrics{$m} out of $host_metrics{$metrics{$m}{'with'}}.."
					if (do_cmp( ($host_metrics{$metrics{$m}{'with'}} <= 0 ? 100 :
						100 - (100 * ($host_metrics{$m} / $host_metrics{$metrics{$m}{'with'}}))),
						$metrics{$m}{'warn'},$metrics{$m}{'crit'},$warn,$crit));
				print $m . ":" . $host_metrics{$m} . "\n" if($verbose>0);
			} elsif ($metrics{$m}{'type'} eq 'glob') {
				# iterate and cmp
				my $cnt = 0;
				foreach (keys %host_metrics) {
					next unless /^$m/;
					print "$_: $host_metrics{$_}.."
						if(do_cmp($host_metrics{$_},$metrics{$m}{'warn'},$metrics{$m}{'crit'},
							$warn,$crit)>0);
					print $_ . ":" . $host_metrics{$_} . "\n" if($verbose>0);
					$cnt++;
				}
				if ($cnt == 0) {
					print "Glob $m: matched no objects..";
					$warn++;
				}
			}
		}
		print "Warnings: $warn.." if ($warn>0);
		print "Criticals: $crit.." if ($crit>0);
		print "\n" if($verbose>0);
		exit 1 if ($warn>0);
		exit 2 if ($crit>0);

    print "<A HREF=\"$$tree[1][4][0]{'AUTHORITY'}?c=$current_cluster&h=$$host[0]{'NAME'}\" target=\"_blank\">Stats ok</A>\n";

		exit 0;
	}
});

print "Host not found!\n";
exit 3;

