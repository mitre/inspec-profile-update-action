control 'SV-224760' do
  title 'The ISEC7 EMM Suite must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Verify the maxConnections setting is set according to organizational guidelines.
Verify the maxThreads setting is set according to organizational guidelines.

If the maxConnections setting is not set according to organizational guidelines or the maxThreads setting is not set according to organizational guidelines, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Set the maxConnections setting according to organizational guidelines.
Set the maxThreads setting according to organizational guidelines.
Restart the ISEC7 EMM Suite Web service.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26451r461536_chk'
  tag severity: 'medium'
  tag gid: 'V-224760'
  tag rid: 'SV-224760r505933_rule'
  tag stig_id: 'ISEC-06-000010'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-26439r461537_fix'
  tag 'documentable'
  tag legacy: ['SV-106407', 'V-97303']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
