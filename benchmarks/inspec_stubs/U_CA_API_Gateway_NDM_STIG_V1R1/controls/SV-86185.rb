control 'SV-86185' do
  title 'The CA API Gateway must protect against or limit the effects of all known types of Denial of Service (DoS) attacks on the CA API Gateway management network by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Verify the CA API Gateway drops packets by default and only puts non-Gateway services on trusted interfaces.
 
Check for the following lines in "/etc/sysconfig/iptables":
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
[0:0] -A INPUT -i eth0 -p udp -m udp --dport 53 -j ACCEPT
[0:0] -A INPUT -i eth2 -p udp -m udp --dport 53 -j ACCEPT
[0:0] -A INPUT -i eth3 -p udp -m udp --dport 53 -j ACCEPT
[0:0] -A INPUT -i eth0 -p udp -m udp --dport 123 -j ACCEPT
[0:0] -A INPUT -i eth2 -p udp -m udp --dport 123 -j ACCEPT
[0:0] -A INPUT -i eth3 -p udp -m udp --dport 123 -j ACCEPT
[0:0] -A INPUT -i eth0 -p tcp -m tcp --dport 3306 -j ACCEPT
[0:0] -A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
 
Check for the following lines in "/etc/sysconfig/ip6tables":
:INPUT DROP [0:0]
[0:0] -A INPUT -i eth0 -p udp -m udp --dport 53 -j ACCEPT
[0:0] -A INPUT -i eth2 -p udp -m udp --dport 53 -j ACCEPT
[0:0] -A INPUT -i eth3 -p udp -m udp --dport 53 -j ACCEPT
[0:0] -A INPUT -i eth0 -p udp -m udp --dport 123 -j ACCEPT
[0:0] -A INPUT -i eth2 -p udp -m udp --dport 123 -j ACCEPT
[0:0] -A INPUT -i eth3 -p udp -m udp --dport 123 -j ACCEPT
[0:0] -A INPUT -i eth0 -p tcp -m tcp --dport 3306 -j ACCEPT
[0:0] -A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
 
If the CA API Gateway does not drop packets by default or puts non-Gateway services on untrusted interfaces, this is a finding.
 
Verify the CA API Gateway logs and drops TCP packets with bad flags.
 
Check for the following lines in "/etc/sysconfig/iptables":
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j badflags
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j badflags
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j badflags
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j badflags
[0:0] -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j badflags
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j badflags
[0:0] -A badflags -m limit --limit 15/min -j LOG --log-prefix "Badflags:"
[0:0] -A badflags -j DROP
 
Check for the following lines in "/etc/sysconfig/ip6tables":
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j badflags6
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j badflags6
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j badflags6
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j badflags6
[0:0] -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j badflags6
[0:0] -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j badflags6
[0:0] -A badflags6 -m limit --limit 15/min -j LOG --log-prefix "Badflags6:"
[0:0] -A badflags6 -j DROP
 
If the CA API Gateway does not log and drop TCP packets with bad flags, this is a finding.
 
Verify the CA API Gateway only allows certain ICMPs and rate limits pings.
 
Check for the following lines in "/etc/sysconfig/iptables":
[0:0] -A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
[0:0] -A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT
[0:0] -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT
[0:0] -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 2/sec -j ACCEPT
[0:0] -A INPUT -p icmp -j badflags
[0:0] -A OUTPUT -p icmp -m state --state INVALID -j DROP
 
Check for the following lines in "/etc/sysconfig/ip6tables":
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 1 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 129 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -m limit --limit 2/sec -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 137 -j ACCEPT
[0:0] -A INPUT -p icmpv6 -j badflags6
 
If the CA API Gateway does not only allow certain ICMPs and rate limits pings, this is a finding.'
  desc 'fix', 'If the "iptables" file is not consistent, replace it with one from the distribution RPM. You may need to add additional permissions if some services are required.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71939r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71561'
  tag rid: 'SV-86185r1_rule'
  tag stig_id: 'CAGW-DM-000310'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-77885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
