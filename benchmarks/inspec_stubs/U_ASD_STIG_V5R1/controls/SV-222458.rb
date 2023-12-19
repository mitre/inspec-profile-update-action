control 'SV-222458' do
  title 'The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', "Review the application documentation and interview the application admin to identify application management interfaces and features.

Access the application management utility and create a test user account or use the account of a regular privileged user who is cooperating with the testing.

Access and open the auditing logs.

Using an admin account, delete some or all of the privileges of a privileged user.

Attempt to delete privileges in a manner that will cause a failure event such as attempting to delete a user’s privileges with an account that doesn't have the rights to do so.

Review the application logs and ensure both events were captured in the logs. The event data should include the user’s identity and the privilege that was granted and the privilege that failed to be granted.

If the application does not log when successful and unsuccessful attempts to delete privileges occur, this is a finding."
  desc 'fix', 'Configure the application to audit successful and unsuccessful attempts to delete privileges.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24128r493282_chk'
  tag severity: 'medium'
  tag gid: 'V-222458'
  tag rid: 'SV-222458r508029_rule'
  tag stig_id: 'APSC-DV-000790'
  tag gtitle: 'SRG-APP-000499'
  tag fix_id: 'F-24117r493283_fix'
  tag 'documentable'
  tag legacy: ['V-69397', 'SV-84019']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
