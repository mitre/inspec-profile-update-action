control 'SV-255253' do
  title 'SSMC web server must use encryption strength in accordance with the categorization of data hosted by the web server when remote connections are provided.'
  desc 'The SSMC web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

Methods of communication are http for publicly displayed information, https to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.

'
  desc 'check', 'Verify that SSMC uses encryption strength equal to the categorization of data hosted by doing the following:

1. Log on to SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following:

$ grep ^ssmc.secure.tls.only /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties
ssmc.secure.tls.only = true

If the command output does not read "ssmc.secure.tls.only = true", this is a finding.'
  desc 'fix', 'Configure SSMC to use encryption strength equal to the categorization of data hosted by doing the following: 

1. Log on to SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Using vi edit ssmc.properties and set "ssmc.secure.tls.only=true". Save and exit.

3. Type "config_appliance" to return to TUI. Restart (stop and start) SSMC services using TUI menu option 2.'
  impact 0.7
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58866r869926_chk'
  tag severity: 'high'
  tag gid: 'V-255253'
  tag rid: 'SV-255253r879519_rule'
  tag stig_id: 'SSMC-WS-010040'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-58810r869927_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000172-WSR-000104', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'SC-8', 'SC-8 (2)', 'SC-8 (2)']
end
