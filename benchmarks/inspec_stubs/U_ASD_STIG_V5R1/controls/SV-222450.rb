control 'SV-222450' do
  title 'The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user is granted access or rights to application features and function not afforded to an ordinary user, they have been granted access to privilege and that action must be logged.'
  desc 'check', "Review the application documentation and interview the application admin to identify application management interfaces and features.

Access the application management utility and create a test user account or use the account of a regular unprivileged user who is cooperating with the testing.

Access and open the auditing logs.

Using an account with the appropriate privileges, grant the user a privilege they previously did not have.

Attempt to grant privileges in a manner that will cause a failure event such as granting privileges to a non-existent user or attempting to grant privileges with an account that doesn't have the rights to do so.

Review the application logs and ensure both events were captured in the logs. The event data should include the user’s identity and the privilege that was granted and the privilege that failed to be granted.

If the application does not log when successful and unsuccessful attempts to grant privilege occur, this is a finding."
  desc 'fix', 'Configure the application to audit successful and unsuccessful attempts to grant privileges.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24120r493258_chk'
  tag severity: 'medium'
  tag gid: 'V-222450'
  tag rid: 'SV-222450r508029_rule'
  tag stig_id: 'APSC-DV-000710'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-24109r493259_fix'
  tag 'documentable'
  tag legacy: ['V-69381', 'SV-84003']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
