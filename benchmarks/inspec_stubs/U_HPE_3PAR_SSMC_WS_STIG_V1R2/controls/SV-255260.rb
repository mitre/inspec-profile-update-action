control 'SV-255260' do
  title 'SSMC web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to re-authenticate guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the web server or an attacker using a hijacked session to slowly probe the web server.'
  desc 'check', 'Verify that SSMC is configured to close web sessions after an absolute period of time by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command: 

$ grep ^server.absolute.session.timeout /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties

server.absolute.session.timeout=60

If the command output does not read "server.absolute.session.timeout=60", this is a finding.'
  desc 'fix', 'Configure SSMC to close web sessions after an absolute period of time by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Use vi editor to locate and set the value of property "server.absolute.session.timeout" to 60 in /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties. Uncomment it if required. Save and exit.

3. Type "config_appliance" to return to TUI. Restart (stop and start) SSMC services using TUI menu option 2.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58873r869947_chk'
  tag severity: 'medium'
  tag gid: 'V-255260'
  tag rid: 'SV-255260r879673_rule'
  tag stig_id: 'SSMC-WS-010150'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-58817r869948_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
