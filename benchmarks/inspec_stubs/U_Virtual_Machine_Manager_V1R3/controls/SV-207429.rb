control 'SV-207429' do
  title 'The VMM must notify the system administrator and ISSO when accounts are disabled.'
  desc 'When VMM accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual VMM users or for identifying the VMM processes themselves.  Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that VMM accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM notifies the system administrator and ISSO when accounts are disabled.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to notify the system administrator and ISSO when accounts are disabled.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7686r365697_chk'
  tag severity: 'medium'
  tag gid: 'V-207429'
  tag rid: 'SV-207429r379327_rule'
  tag stig_id: 'SRG-OS-000276-VMM-000980'
  tag gtitle: 'SRG-OS-000276'
  tag fix_id: 'F-7686r365698_fix'
  tag 'documentable'
  tag legacy: ['V-57059', 'SV-71319']
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
