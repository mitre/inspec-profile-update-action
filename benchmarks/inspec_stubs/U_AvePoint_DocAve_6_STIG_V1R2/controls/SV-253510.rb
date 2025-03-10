control 'SV-253510' do
  title 'DocAve must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Check the DocAve Manager Maximum User Session setting.
- Log on to DocAve with admin account.
- On the Control Panel page, in the System Options section, click "Security Settings". 
- Select the "System Security Policy" tab.
- Verify that Specify a maximum number of user sessions is set to "3" or less.

If Maximum number of user sessions is not set to "3" or less, this is a finding.'
  desc 'fix', 'Configure the DocAve Manager Maximum User Session setting.
- Log on to DocAve with admin account.
- On the Control Panel page, in the System Options section, click "Security Settings". 
- Select the "System Security Policy" tab.
- Set Maximum number of user sessions to "3" or less. 
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56962r836503_chk'
  tag severity: 'medium'
  tag gid: 'V-253510'
  tag rid: 'SV-253510r836505_rule'
  tag stig_id: 'DCAV-00-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-56913r836504_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
