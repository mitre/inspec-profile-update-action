control 'SV-256839' do
  title 'Compliance Guardian must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be satisfied by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Check the Compliance Guardian Manager Maximum User Session setting.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the System Configuration section, click "General Settings".
- Select "Security - System Security Policy".
- Verify that the "Specify a maximum simultaneous logons for the same user" is set to "5".

If the maximum number of user sessions is higher than 5, this is a finding.'
  desc 'fix', 'Configure the Compliance Guardian Manager Maximum User Session setting.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the System Configuration section, click "General Settings".
- Select "Security - System Security Policy".
- Set the maximum simultaneous logons for the same user option to "5".
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60514r890125_chk'
  tag severity: 'medium'
  tag gid: 'V-256839'
  tag rid: 'SV-256839r890127_rule'
  tag stig_id: 'APCG-00-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-60457r890126_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
