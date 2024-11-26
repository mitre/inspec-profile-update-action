control 'SV-253873' do
  title 'The Tanium application must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can ensure sessions that are not closed when the user logs out of an application are eventually closed.

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" at top center of the screen.

3. Under "Configuration", select "Platform Settings".

4. In the "Filter Items" box, enter "max_console_idle_seconds".

If no results are returned, this is a finding.

If results are returned for "max_console_idle_seconds" but the value is not "900" or less, this is a finding.'
  desc 'fix', 'If the "max_console_idle_seconds" setting exists but is not "900" or less: 

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Platform Settings".

4. In the "Filter Items" box, enter "max_console_idle_seconds".

5. Select the "max_console_idle_seconds" setting.

6. For "Value", enter "900" or less.

7. Click the "Save" button.

If the "max_console_idle_seconds" setting does not exist:

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Platform Settings".

4. Click the "Create Setting" button at the top right.

5. Select "Server" box for "Setting Type".

6. In "Create Platform Setting" dialog box, enter "max_console_idle_seconds" for "Name".

7. Select "Numeric" for the "Value Type".

8. For the "Value", enter "900" or less.

9. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57325r842645_chk'
  tag severity: 'medium'
  tag gid: 'V-253873'
  tag rid: 'SV-253873r850135_rule'
  tag stig_id: 'TANS-SV-000067'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-57276r842646_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
