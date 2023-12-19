control 'SV-242195' do
  title 'The TPS must block malicious ICMP packets by properly configuring ICMP signatures and rules.'
  desc 'Internet Control Message Protocol (ICMP) messages are used to provide feedback about problems in the network. These messages are sent back to the sender to support diagnostics. However, some messages can also provide host information, network topology, and a covert channel that may be exploited by an attacker.

Given the prevalence of ICMP traffic on the network, monitoring for malicious ICMP traffic would be cumbersome. Vendors provide signatures and rules which filter for known ICMP traffic exploits.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "icmp". 

If the following filter names are not set to Block+Notify, this is a finding:

7141: ICMP: Header Incomplete
7145: ICMPv6: Header Incomplete
0087: ICMP: Modem Hangup (+++ATH) Echo Request
0110: TFN: ICMP Flood Command Acknowledgement (General)
0282: ICMP: icmpenum (Timestamp Request)
0283: ICMP: icmpenum (Information Request)
1474: ICMP: Modem Hangup (+++ATH) Echo Reply
3852: NTRootKit: Command and Control Response (ICMP)
5855: ICMP: Malicious Router Discovery Protocol Packet
10043: ICMP: Solaris 10 ICMP Remote DoS
12522: ICMP: Source Quench
12577: ICMP: Destination Unreachable (Fragmentation Needed and DF Bit Set)
13118: ICMP: Windows DirectAccess Server IPv6 Invalid Header Denial-of-Service Vulnerability
13172: ICMP: Active Directory LDAP Winsock Denial-of-Service Vulnerability
13532: IPv6: Microsoft Windows ICMPv6 Prefix Update Denial-of-Service Vulnerability
17049: ICMPv6: FreeBSD rtsold Buffer Overflow Vulnerability
17086: ICMP: Regin Malware Communication Attempt
22646: ICMPv6: FreeBSD SCTP ICMPv6 Denial-of-Service Vulnerability
29732: ICMP: Dnsmasq ICMPv6 Router Advertisement Buffer Overflow Vulnerability
0081: ICMP: Unassigned Type (Type 1)
0081: ICMP: Unassigned Type (Type 1)
ICMPv6 Types 144 through 153)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "icmp". 
5. Click each of the following rules and select:

7141: ICMP: Header Incomplete
7145: ICMPv6: Header Incomplete
0087: ICMP: Modem Hangup (+++ATH) Echo Request
0110: TFN: ICMP Flood Command Acknowledgement (General)
0282: ICMP: icmpenum (Timestamp Request)
0283: ICMP: icmpenum (Information Request)
1474: ICMP: Modem Hangup (+++ATH) Echo Reply
3852: NTRootKit: Command and Control Response (ICMP)
5855: ICMP: Malicious Router Discovery Protocol Packet
10043: ICMP: Solaris 10 ICMP Remote DoS
12522: ICMP: Source Quench
12577: ICMP: Destination Unreachable (Fragmentation Needed and DF Bit Set)
13118: ICMP: Windows DirectAccess Server IPv6 Invalid Header Denial-of-Service Vulnerability
13172: ICMP: Active Directory LDAP Winsock Denial-of-Service Vulnerability
13532: IPv6: Microsoft Windows ICMPv6 Prefix Update Denial-of-Service Vulnerability
17049: ICMPv6: FreeBSD rtsold Buffer Overflow Vulnerability
17086: ICMP: Regin Malware Communication Attempt
22646: ICMPv6: FreeBSD SCTP ICMPv6 Denial-of-Service Vulnerability
29732: ICMP: Dnsmasq ICMPv6 Router Advertisement Buffer Overflow Vulnerability
0081: ICMP: Unassigned Type (Type 1)
0081: ICMP: Unassigned Type (Type 1)
ICMPv6 Types 144 through 153)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45470r710126_chk'
  tag severity: 'medium'
  tag gid: 'V-242195'
  tag rid: 'SV-242195r710128_rule'
  tag stig_id: 'TIPP-IP-000300'
  tag gtitle: 'SRG-NET-000273-IDPS-00204'
  tag fix_id: 'F-45428r710127_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
