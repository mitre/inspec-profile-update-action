control 'SV-255252' do
  title 'SSMC web server must limit the number of allowed simultaneous session requests.'
  desc 'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks. 

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DOD direction. While the DOD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'Verify that SSMC limits the number of concurrent sessions by doing the following:

1. Log on to SSMC TUI via SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following commands:

$ grep ^security.max.active.ui.sessions /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties

security.max.active.ui.sessions=10

$ grep ^security.max.active.per.user.sessions /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties
security.max.active.per.user.sessions=1

If the output of the above commands does not show the values for "security.max.active.ui.sessions" and "security.max.active.per.user.sessions" properties with values set as "10" and "1" respectively, this is a finding.'
  desc 'fix', 'Configure SSMC to limit the number of allowed simultaneous web session requests by doing the following:

1. Log on to SSMC TUI via SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Edit /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties (Use vi to edit).

3. Locate (or add a fresh entry) property security.max.active.ui.sessions. Set the value to "10".

4. Locate (or add a fresh entry) property security.max.active.per.user.sessions. Set the value to "1".

5. Save the file and exit.

6. Type "config_appliance" to return to TUI. Restart (stop and start) SSMC services using TUI menu option 2.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58865r869923_chk'
  tag severity: 'medium'
  tag gid: 'V-255252'
  tag rid: 'SV-255252r870275_rule'
  tag stig_id: 'SSMC-WS-010020'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-58809r869924_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
