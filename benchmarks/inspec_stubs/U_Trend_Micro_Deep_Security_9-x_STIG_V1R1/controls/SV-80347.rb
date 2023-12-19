control 'SV-80347' do
  title 'Trend Deep Security must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the number of concurrent sessions is limited to one.

In the administration console go to: 
System Settings >> Security >> Number of concurrent sessions allowed per User 

Review the policy to ensure no more than 1 session is permitted.

If more than 1 session is permitted this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to limit the number of concurrent sessions to one.

Set the current session limit to 1.

Administration >> System Settings >> Security >> Number of concurrent sessions allowed per User >> 1'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66505r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65857'
  tag rid: 'SV-80347r1_rule'
  tag stig_id: 'TMDS-00-000005'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-71933r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
