control 'SV-254927' do
  title 'The Tanium application must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that sessions not closed through the user logging out of an application are eventually closed.

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

1. Log on with multi-factor authentication.

2. Click "Administration" at top center of the screen.

3. Select the "Global Settings" under "Management".

4. In "Filter Items" box, enter "max_console_idle_seconds".

If no results are returned, this is a finding.

If results are returned for "max_console_idle_seconds", but the value is not "900" or less, this is a finding.'
  desc 'fix', 'In the event the "max_console_idle_seconds" setting exists, but is not "900" or less: 

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Platform Settings".

4. In the "Filter Items" box, enter "max_console_idle_seconds".

5. Select the "max_console_idle_seconds" setting.

6. Enter "900" or less for "Value".

7. Click "Save".


In the event the "max_console_idle_seconds" setting does not exist:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Platform Settings".

4. Click "Create Setting" in the top right.

5. Select "Server" for "Setting Type".

6. In "Create Platform Setting" dialog box, enter "max_console_idle_seconds" for "Name".

7. Select "Numeric" for the "Value Type".

8. Enter "900" or less for the "Value".

9. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58540r867679_chk'
  tag severity: 'medium'
  tag gid: 'V-254927'
  tag rid: 'SV-254927r867681_rule'
  tag stig_id: 'TANS-AP-000720'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-58484r867680_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
