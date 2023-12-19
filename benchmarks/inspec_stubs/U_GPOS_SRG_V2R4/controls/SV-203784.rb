control 'SV-203784' do
  title 'The operating system must enable an application firewall, if available.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Verify the operating system enabled an application firewall, if available. If it does not, this is a finding. If the operating system does not support an application firewall, this may be downgraded to a CAT III finding.'
  desc 'fix', "Ensure the operating system's application firewall is enabled, if available."
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3909r375743_chk'
  tag severity: 'medium'
  tag gid: 'V-203784'
  tag rid: 'SV-203784r388482_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00232'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-3909r375744_fix'
  tag 'documentable'
  tag legacy: ['SV-70833', 'V-56573']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
