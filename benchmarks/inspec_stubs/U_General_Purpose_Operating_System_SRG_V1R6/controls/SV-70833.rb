control 'SV-70833' do
  title 'The operating system must enable an application firewall, if available.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Verify the operating system enabled an application firewall, if available. If it does not, this is a finding. If the operating system does not support an application firewall, this may be downgraded to a CAT III finding.'
  desc 'fix', "Ensure the operating system's application firewall is enabled, if available."
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57141r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56573'
  tag rid: 'SV-70833r1_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00232'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-61467r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
