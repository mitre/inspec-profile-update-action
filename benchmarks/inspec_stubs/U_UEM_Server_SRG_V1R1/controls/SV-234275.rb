control 'SV-234275' do
  title 'The UEM server must limit the number of concurrent sessions per privileged user account to three or less concurrent sessions.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431010'
  desc 'check', 'Verify the UEM server limits the number of concurrent sessions per privileged user account to three or less concurrent sessions.

If the UEM server does not limit the number of concurrent sessions per privileged user account to three or less concurrent sessions, this is a finding.'
  desc 'fix', 'Configure the UEM server to limit the number of concurrent sessions per privileged user account to three or less concurrent sessions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37460r617394_chk'
  tag severity: 'medium'
  tag gid: 'V-234275'
  tag rid: 'SV-234275r617395_rule'
  tag stig_id: 'SRG-APP-000001-UEM-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-37425r617395_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
