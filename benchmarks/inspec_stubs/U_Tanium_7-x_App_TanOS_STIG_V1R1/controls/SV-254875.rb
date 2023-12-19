control 'SV-254875' do
  title 'The Tanium max_soap_sessions_per_user setting must be explicitly enabled to limit the number of simultaneous sessions.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.
 
This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built in to the application.
 
This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and logon with multi-factor authentication.
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Configuration," select "Platform Settings".
 
4. In the "Filter items" search box, type "max_soap_sessions_per_user".
 
5. Click "Enter".
 
If no results are returned, this is a finding.
 
If results are returned for "max_soap_sessions_per_user", but the value is not "1024", this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.
 
2. Click "Administration" on the top navigation banner. 

3. Under "Configuration," select "Platform Settings". 

4. Click "Create Setting". 

5. Select "Server" for "Setting Type".

6. In the "Create Platform Setting" dialog box, enter "max_soap_sessions_per_user" for "Name". 

7. Select the "Numeric" radio button from "Value Type".

8. Enter "1024" for the "Value:". 

9. Click "Save". 

10. Add this setting to the system documentation for validation.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58488r867523_chk'
  tag severity: 'medium'
  tag gid: 'V-254875'
  tag rid: 'SV-254875r867525_rule'
  tag stig_id: 'TANS-AP-000010'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-58432r867524_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
