control 'SV-222462' do
  title 'The application must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Knowing when a user successfully or unsuccessfully logged on to the application is critical information that aids in forensic analysis.'
  desc 'check', 'Review and monitor the application logs.

Authenticate to the application and observe if the log includes an entry to indicate the user’s authentication was successful.

Terminate the user session by logging out.

Reauthenticate using invalid user credentials and observe if the log includes an entry to indicate the authentication was unsuccessful.

If successful and unsuccessful logon events are not recorded in the logs, this is a finding.'
  desc 'fix', 'Configure the application or application server to write a log entry when successful and unsuccessful logon events occur.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24132r493294_chk'
  tag severity: 'medium'
  tag gid: 'V-222462'
  tag rid: 'SV-222462r879874_rule'
  tag stig_id: 'APSC-DV-000830'
  tag gtitle: 'SRG-APP-000503'
  tag fix_id: 'F-24121r493295_fix'
  tag 'documentable'
  tag legacy: ['SV-84027', 'V-69405']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
