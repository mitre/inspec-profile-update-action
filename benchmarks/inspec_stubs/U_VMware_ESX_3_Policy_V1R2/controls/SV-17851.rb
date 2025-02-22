control 'SV-17851' do
  title 'ESX administrators have not received proper training to administer the ESX Server.'
  desc 'Different roles require different types of training. A skilled staff is one of the critical components to the security of an organization.  The ESX Server is complex and has many components that need to be monitored and configured.  If staff is not properly trained in administering the ESX Server, vulnerabilities will likely be open.'
  desc 'check', 'Request a copy of the ESX Server training documentation for all staff administering the ESX Servers and peripheral systems.  If no training documentation can be produced, this is a finding.'
  desc 'fix', 'Train all the ESX Server administrators.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-17448r1_chk'
  tag severity: 'low'
  tag gid: 'V-16851'
  tag rid: 'SV-17851r1_rule'
  tag stig_id: 'ESX0828'
  tag gtitle: 'ESX admins have not received proper training'
  tag fix_id: 'F-16699r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
