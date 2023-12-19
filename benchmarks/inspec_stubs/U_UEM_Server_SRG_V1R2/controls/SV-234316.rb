control 'SV-234316' do
  title 'The UEM server must notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).'
  desc 'Users need to be aware of activity that occurs regarding their application account. Providing users with information regarding the number of unsuccessful attempts made to log in to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

This requirement is intended to cover both traditional logons to information systems and general accesses to information systems that occur in other types of architectural configurations (e.g., service-oriented architectures).'
  desc 'check', 'Verify the UEM server notifies the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).

If the UEM server does not notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access), this is a finding.'
  desc 'fix', 'Configure the UEM server to notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37501r613958_chk'
  tag severity: 'medium'
  tag gid: 'V-234316'
  tag rid: 'SV-234316r879552_rule'
  tag stig_id: 'SRG-APP-000076-UEM-000042'
  tag gtitle: 'SRG-APP-000076'
  tag fix_id: 'F-37466r613959_fix'
  tag 'documentable'
  tag cci: ['CCI-000053']
  tag nist: ['AC-9 (1)']
end
