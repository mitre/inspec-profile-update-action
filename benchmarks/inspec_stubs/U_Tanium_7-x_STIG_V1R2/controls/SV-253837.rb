control 'SV-253837' do
  title 'The Tanium Application Server console must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc 'When multifactor authentication is enabled, the Tanium Console will initiate a session lock based on the ActivClient or other smartcard software.
 
By initiating the session lock, the console will be locked and not allow unauthorized access by anyone other than the original user.
 
Although this setting does not apply when multifactor authentication is enabled, it should be explicitly disabled in the event multifactor authentication is ever broken or removed.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Configuration", select "Platform Settings".
 
4. In the "Filter items" search box, type "max_console_idle_seconds".
 
5. Click "Enter".
 
If no results are returned, this is a finding.
 
If results are returned for "max_console_idle_seconds", but the value is not between the range of "1 - 900", this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "Platform Settings". 

4. Click "Create Setting". 

5. Select "Server" box for "Setting Type".

6. In " Create Platform Setting" dialog box enter "max_console_idle_seconds" for "Name".
 
7. Select "Numeric" radio button from "Value Type".

8. Select "Value" and enter a value between the range of "1 - 900". 

9. Click "Save".

10. Add this setting to the system documentation for validation.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57289r842537_chk'
  tag severity: 'medium'
  tag gid: 'V-253837'
  tag rid: 'SV-253837r842539_rule'
  tag stig_id: 'TANS-SV-000002'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-57240r842538_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
