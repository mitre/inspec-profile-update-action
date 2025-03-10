control 'SV-205439' do
  title 'The Mainframe Product must limit the number of concurrent sessions to three for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by using information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  desc 'check', 'If the Mainframe Product has no log on capability, this requirement is not applicable. 

Examine installation and configuration settings.

If concurrent sessions are not limited to three per account by type of user, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to limit current sessions to three per account by type of user.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5705r299550_chk'
  tag severity: 'medium'
  tag gid: 'V-205439'
  tag rid: 'SV-205439r395442_rule'
  tag stig_id: 'SRG-APP-000001-MFP-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-5705r299551_fix'
  tag 'documentable'
  tag legacy: ['SV-82291', 'V-67801']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
