control 'SV-222464' do
  title 'The application must generate audit records showing starting and ending time for user access to the system.'
  desc 'Knowing when a user’s application session began and when it ended is critical information that aids in forensic analysis.'
  desc 'check', 'Review and monitor the application logs.

Initiate a user session and observe if the log includes a time stamp showing the start of the session.

Terminate the user session and observe if the log includes a time stamp showing the end of the session.

If the start and the end time of the session are not recorded in the logs, this is a finding.'
  desc 'fix', 'Configure the application or application server to record the start and end time of user session activity.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24134r493300_chk'
  tag severity: 'medium'
  tag gid: 'V-222464'
  tag rid: 'SV-222464r879876_rule'
  tag stig_id: 'APSC-DV-000850'
  tag gtitle: 'SRG-APP-000505'
  tag fix_id: 'F-24123r493301_fix'
  tag 'documentable'
  tag legacy: ['SV-84031', 'V-69409']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
