control 'SV-218685' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'check', 'Verify no interface is configured to use DHCP.

# grep -i bootproto=dhcp /etc/sysconfig/network-scripts/ifcfg-*

If any configuration is found, this is a finding.'
  desc 'fix', 'Edit the "/etc/sysconfig/network-scripts/ifcfg-*" file(s) and change the "bootproto" setting to "static".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20160r556469_chk'
  tag severity: 'medium'
  tag gid: 'V-218685'
  tag rid: 'SV-218685r603259_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20158r556470_fix'
  tag 'documentable'
  tag legacy: ['V-22548', 'SV-63411']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
