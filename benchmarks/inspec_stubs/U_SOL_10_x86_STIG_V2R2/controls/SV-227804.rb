control 'SV-227804' do
  title 'The system must log martian packets.'
  desc 'Martian packets are packets containing addresses known by the system to be invalid.  Logging these messages allows the SA to identify misconfigurations or attacks in progress.'
  desc 'check', "If the system is not a global zone, this vulnerability is not applicable.

Determine if the system is configured to log martian packets.  Examine the IPF rules on the system.

Procedure:
# ipfstat -i

There must be rules logging inbound traffic containing invalid source addresses, which minimally include the system's own addresses and broadcast addresses for attached subnets.  If such rules do not exist, this is a finding."
  desc 'fix', "Configure the system to log martian packets using IPF.  Add rules logging inbound traffic containing invalid source addresses, which minimally include the system's own addresses and broadcast addresses for attached subnets.

For example, consider a system with a single network connection having IP address 192.168.1.10 with a local subnet broadcast address of 192.168.1.255.  Packets with source addresses of 192.168.1.10 and 192.168.1.255 must be logged if received by the system from the network connection.

Edit /etc/ipf/ipf.conf and add the following rules, substituting local addresses and interface names:
block in log quick on ce0 from 192.168.1.10 to any
block in log quick on ce0 from 192.168.1.255 to any

Reload the IPF rules.
Procedure:
# ipf -Fa -A -f /etc/ipf/ipf.conf"
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36467r603004_chk'
  tag severity: 'low'
  tag gid: 'V-227804'
  tag rid: 'SV-227804r603266_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-36431r603005_fix'
  tag 'documentable'
  tag legacy: ['V-22418', 'SV-29773']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
