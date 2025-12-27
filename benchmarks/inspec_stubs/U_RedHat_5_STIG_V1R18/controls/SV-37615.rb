control 'SV-37615' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'check', 'Verify no interface is configured to use DHCP.
# grep -i bootproto=dhcp /etc/sysconfig/network-scripts/ifcfg-*
If any configuration is found, this is a finding.'
  desc 'fix', 'Edit the "/etc/sysconfig/network-scripts/ifcfg-*" file(s) and change the "bootproto" setting to "static".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22548'
  tag rid: 'SV-37615r1_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'GEN007840'
  tag fix_id: 'F-24173r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
