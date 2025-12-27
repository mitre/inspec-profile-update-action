control 'SV-91155' do
  title 'The Akamai Luna Portal must notify the administrator of the number of successful login attempts.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the date and time of their last successful login allows the administrator to determine if any unauthorized activity has occurred. This incorporates all methods of login, including but not limited to SSH, HTTP, HTTPS, and physical connectivity. The organization-defined time period is dependent on the frequency with which administrators typically log in to the network device.'
  desc 'check', 'Verify the activity log is showing user login data:

1. Log in to the Luna Portal.
2. Verify that one of the four widgets includes the activity log.

If the activity log is not showing, this is a finding.'
  desc 'fix', 'Configure the activity log to appear in the "My Akamai" section.

1. Select the gear icon on one of the four widgets.
2. Select the activity log in the left column.
3. Check the box for "All Logins".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76119r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76459'
  tag rid: 'SV-91155r1_rule'
  tag stig_id: 'AKSD-DM-000006'
  tag gtitle: 'SRG-APP-000516-NDM-000332'
  tag fix_id: 'F-83137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001391']
  tag nist: ['CM-6 b', 'AC-9 (2)']
end
