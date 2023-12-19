control 'SV-207430' do
  title 'The VMM must notify the system administrator and ISSO when accounts are removed.'
  desc 'When VMM accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual VMM users or for identifying the VMM processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that VMM accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM notifies the system administrator and ISSO when accounts are removed.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to notify the system administrator and ISSO when accounts are removed.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7687r365700_chk'
  tag severity: 'medium'
  tag gid: 'V-207430'
  tag rid: 'SV-207430r379330_rule'
  tag stig_id: 'SRG-OS-000277-VMM-000990'
  tag gtitle: 'SRG-OS-000277'
  tag fix_id: 'F-7687r365701_fix'
  tag 'documentable'
  tag legacy: ['V-57061', 'SV-71321']
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
