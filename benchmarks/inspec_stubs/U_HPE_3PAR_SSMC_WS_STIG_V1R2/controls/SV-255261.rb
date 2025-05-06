control 'SV-255261' do
  title 'SSMC web server must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', 'Verify that idle session timeout is set by doing the following:

1. Log on to SSMC administrator console as ssmcadmin. 

2. Navigate to Actions >> Preferences.

3. Locate Session timeout property and check if it is set to 10 minutes.

If the value is not set to 10 minutes, this is a finding.'
  desc 'fix', 'Configure idle session timeouts on the web GUI by doing the following:

1. Log on to SSMC administrator console as ssmcadmin.

2. Navigate to Actions >> Preferences.

3. Locate Session timeout property and update the value to 10 minutes.

4. Restart SSMC services from appliance TUI menu option 2.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58874r869950_chk'
  tag severity: 'medium'
  tag gid: 'V-255261'
  tag rid: 'SV-255261r879673_rule'
  tag stig_id: 'SSMC-WS-010160'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-58818r869951_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
