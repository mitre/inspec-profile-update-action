control 'SV-234255' do
  title 'The application must limit the number of concurrent sessions to three.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Open Citrix Studio, select "Policy Panel", check for Computer Policies. 

Maximum number of sessions (MaximumNumberOfSessions) policy is "ENABLED" and explicitly applied to Linux Desktop/Application Delivery Groups.

If Maximum Number of Sessions policy is "DISABLED" or limit not set to "3", this is a finding.'
  desc 'fix', 'Open Citrix Studio, select "Policy Panel", check for Computer Policies.

Maximum number of sessions (MaximumNumberOfSessions) policy set to "ENABLED" and limit set to "3".'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x LVDA'
  tag check_id: 'C-37440r612319_chk'
  tag severity: 'medium'
  tag gid: 'V-234255'
  tag rid: 'SV-234255r628796_rule'
  tag stig_id: 'LVDA-VD-000005'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-37405r612320_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
