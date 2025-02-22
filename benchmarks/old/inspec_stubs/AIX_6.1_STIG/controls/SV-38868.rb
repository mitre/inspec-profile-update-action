control 'SV-38868' do
  title 'The system must log martian packets.'
  desc 'Martian packets are packets containing addresses known by the system to be invalid.  Logging these messages allows the SA to identify misconfigurations or attacks in progress.'
  desc 'check', "Determine if the system is configured to log martian packets. Examine the IPF rules on the system.

# lsfilt -a

There must be rules to log inbound traffic containing invalid source addresses, which minimally include the system's own addresses and broadcast addresses for attached subnets. If no such rules exist, this is a finding."
  desc 'fix', "Configure the system to log martian packets.

Add rules to log inbound traffic containing invalid source addresses, which minimally include the system's own addresses and broadcast addresses for attached subnets.

For example, consider a system with a single network connection having IP address 192.168.1.10 with a local subnet broadcast address of 192.168.1.255. 
Packets with source addresses of 192.168.1.10 and 192.168.1.255 must be logged if received by the system from the network connection.
Use the smit utility or genfilt command to add logging of martian packets (packets with a source address of 192.168.1.10 and 192.168.1.255).

# smitty ipsec4

OR

# genfilt -v4 -a P -s 192.168.1.10 -m 0.0.0.0 -d 0.0.0.0 -M -0.0.0.0 -c all -o any -O any -p 0 -P 0 -w I  -l y -i en0 
# genfilt -v4 -a P -s 192.168.1.255 -m 0.0.0.0 -d 0.0.0.0 -M -0.0.0.0 -c all -o any -O any -p 0 -P 0 -w I  -l y -i en0"
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37862r1_chk'
  tag severity: 'low'
  tag gid: 'V-22418'
  tag rid: 'SV-38868r1_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'GEN003611'
  tag fix_id: 'F-33122r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
