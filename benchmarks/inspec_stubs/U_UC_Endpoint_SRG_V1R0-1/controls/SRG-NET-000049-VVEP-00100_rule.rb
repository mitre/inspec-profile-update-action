control 'SRG-NET-000049-VVEP-00100_rule' do
  title 'The Unified Communications Endpoint must notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

This applies to network elements that have the concept of a user account and have the login function residing on the network element.'
  desc 'check', 'Verify that the Unified Communications Endpoint notifies the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).

If the Unified Communications Endpoint does not notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access), this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).'
  impact 0.5
  tag check_id: 'C-SRG-NET-000049-VVEP-00100_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000049-VVEP-00100'
  tag rid: 'SRG-NET-000049-VVEP-00100_rule'
  tag stig_id: 'SRG-NET-000049-VVEP-00100'
  tag gtitle: 'SRG-NET-000049-VVEP-00100'
  tag fix_id: 'F-SRG-NET-000049-VVEP-00100_fix'
  tag 'documentable'
  tag cci: ['CCI-000053']
  tag nist: ['AC-9 (1)']
end
