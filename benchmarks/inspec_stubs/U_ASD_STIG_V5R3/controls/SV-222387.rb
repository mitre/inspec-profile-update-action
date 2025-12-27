control 'SV-222387' do
  title 'The application must provide a capability to limit the number of logon sessions per user.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server or other underlying solution that provides specialized session management capabilities.

If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application.

This requirement addresses concurrent sessions for individual system accounts and does not address concurrent sessions by single users via multiple system accounts.

The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'For production environments;  Review the system documentation, identify the number of application user logon sessions allowed per user, identify the methods utilized for user session management or have application administrator describe how the application implements user session management.

Utilize the management interface that is used to set the user session values, or examine configuration files in order to review user session configuration settings.

Ensure the number of sessions allowed per user is specified in accordance with the organizational requirements.

For development environments;  have the developer provide design documentation or demonstrate how the application is designed to limit the number of simultaneous user logon sessions.

If the application is not configured to limit the number of logon sessions per user as defined by the organization, this is a finding.'
  desc 'fix', 'Design and configure the application to specify the number of logon sessions that are allowed per user.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24057r493069_chk'
  tag severity: 'medium'
  tag gid: 'V-222387'
  tag rid: 'SV-222387r879511_rule'
  tag stig_id: 'APSC-DV-000010'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-24046r493070_fix'
  tag 'documentable'
  tag legacy: ['V-69239', 'SV-83861']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
