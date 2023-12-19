control 'SV-91153' do
  title 'Upon successful login, the Akamai Luna Portal must notify the administrator of the date and time of the last login.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the date and time of their last successful login allows them to determine if any unauthorized activity has occurred. This incorporates all methods of login, including but not limited to SSH, HTTP, HTTPS, and physical connectivity.'
  desc 'check', 'Verify that the activity log is showing user login data:

1. Log in to the Luna Portal.
2. Verify that one of the four widgets includes the activity log.

If the activity log is not showing, this is a finding.'
  desc 'fix', 'Configure the activity log to appear in the "My Akamai" section.

1. Select the gear icon on one of the four widgets.
2. Select the activity log in the left column.
3. Check the box for "All Logins".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76117r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76457'
  tag rid: 'SV-91153r1_rule'
  tag stig_id: 'AKSD-DM-000005'
  tag gtitle: 'SRG-APP-000075-NDM-000217'
  tag fix_id: 'F-83135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000052', 'CCI-000366']
  tag nist: ['AC-9', 'CM-6 b']
end
