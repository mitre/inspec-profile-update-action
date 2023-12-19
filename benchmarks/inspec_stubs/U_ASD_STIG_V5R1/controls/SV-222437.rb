control 'SV-222437' do
  title 'The application must display the time and date of the users last successful logon.'
  desc 'Providing a last successful logon date and time stamp notification to the user when they authenticate and access the application allows the user to determine if their application account has been used without their knowledge. 

Armed with that information, the user can notify the application administrator and initiate a forensics investigation to identify root cause.  Without providing this information to the user, a potential compromise of user accounts could go unnoticed.'
  desc 'check', 'Review the application documentation and interview the application administrator.

If the application does not provide a user interface, this requirement is not applicable.

Logon to the application as a test user and verify successful authentication by creating test data, navigating the application functionality or otherwise utilizing the application.

Note the date and time access was granted.

Log out of the application.

Re-authenticate to the application as the same user.

Validate the last logon date and time is displayed in the user interface. 

If the date and time the user account was last granted access to the application is not displayed in the user interface, this is a finding.'
  desc 'fix', 'Design and configure the application to display the date and time when the user was last successfully granted access to the application.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24107r493219_chk'
  tag severity: 'low'
  tag gid: 'V-222437'
  tag rid: 'SV-222437r508029_rule'
  tag stig_id: 'APSC-DV-000580'
  tag gtitle: 'SRG-APP-000075'
  tag fix_id: 'F-24096r493220_fix'
  tag 'documentable'
  tag legacy: ['V-69355', 'SV-83977']
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
