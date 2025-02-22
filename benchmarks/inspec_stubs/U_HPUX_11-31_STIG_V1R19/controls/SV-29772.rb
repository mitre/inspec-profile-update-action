control 'SV-29772' do
  title 'The system must log martian packets.'
  desc 'Martian packets are packets containing addresses known by the system to be invalid. Logging these messages allows the SA to identify misconfigurations or attacks in progress.'
  desc 'check', "Determine if the system is configured to log martian packets. Examine 
the IPF rules on the system.
# ipfstat -i

There must be rules that log inbound traffic containing invalid source addresses, which minimally include the system's own addresses and broadcast addresses for attached subnets. For example, consider a system with a single network connection having IP address 192.168.1.10 with a local subnet broadcast address of 192.168.1.255. Packets with source addresses of 192.168.1.10 and 192.168.1.255 must be logged if received by the system from the network connection. The /etc/opt/ipf/ipf.conf file would appear as follows:

block in log quick on lan0 from 192.168.1.10 to any
block in log quick on lan0 from 192.168.1.255 to any

If such rules do not exist, this is a finding."
  desc 'fix', "Configure the system to log martian packets using IPF.  Add 
rules that log inbound traffic containing invalid source addresses, 
which minimally include the system's own addresses and broadcast addresses 
for attached subnets.

For example, consider a system with a single network connection having IP 
address 192.168.1.10 with a local subnet broadcast address of 192.168.1.255. 
Packets with source addresses of 192.168.1.10 and 192.168.1.255 must be 
logged if received by the system from the network connection.

Edit /etc/opt/ipf/ipf.conf and add the following rules, substituting local 
addresses and interface names:
block in log quick on lan0 from 192.168.1.10 to any
block in log quick on lan0 from 192.168.1.255 to any

Reload the IPF rules. Flush the rules from your ruleset using the -Fa option. 
The -A option specifies the active rules list. The -f option specifies the rules
configuration file to be used:

# ipf -Fa -A -f /etc/opt/ipf/ipf.conf"
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36511r2_chk'
  tag severity: 'low'
  tag gid: 'V-22418'
  tag rid: 'SV-29772r1_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'GEN003611'
  tag fix_id: 'F-31871r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
