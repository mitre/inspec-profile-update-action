control 'SV-239549' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on SLES for vRealize  by exchanging information with a DHCP server.'
  desc 'check', 'Check that no interface is configured to use "DHCP":

# grep -i bootproto=dhcp4 /etc/sysconfig/network/ifcfg-*

If any configuration is found, this is a finding.'
  desc 'fix', 'Edit the "/etc/sysconfig/network/ifcfg-*" file(s) and change the "bootproto" setting to "static".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42782r662096_chk'
  tag severity: 'medium'
  tag gid: 'V-239549'
  tag rid: 'SV-239549r662098_rule'
  tag stig_id: 'VROM-SL-000650'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42741r662097_fix'
  tag 'documentable'
  tag legacy: ['SV-99219', 'V-88569']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
