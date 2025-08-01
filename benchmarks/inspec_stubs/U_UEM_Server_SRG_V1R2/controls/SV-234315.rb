control 'SV-234315' do
  title 'The UEM server must notify the user, upon successful logon (access) to the application, of the date and time of the last logon (access).'
  desc 'Users need to be aware of activity that occurs regarding their application account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

This requirement is intended to cover both traditional interactive logons to information systems and general accesses to information systems that occur in other types of architectural configurations (e.g., service-oriented architectures).'
  desc 'check', 'Verify the UEM server notifies the user, upon successful logon (access) to the application, of the date and time of the last logon (access).

If the UEM server does not notify the user, upon successful logon (access) to the application, of the date and time of the last logon (access), this is a finding.'
  desc 'fix', 'Configure the UEM server to notify the user, upon successful logon (access) to the application, of the date and time of the last logon (access).'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37500r613955_chk'
  tag severity: 'medium'
  tag gid: 'V-234315'
  tag rid: 'SV-234315r879551_rule'
  tag stig_id: 'SRG-APP-000075-UEM-000041'
  tag gtitle: 'SRG-APP-000075'
  tag fix_id: 'F-37465r613956_fix'
  tag 'documentable'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
