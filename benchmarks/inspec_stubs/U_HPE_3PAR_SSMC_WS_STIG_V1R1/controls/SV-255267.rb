control 'SV-255267' do
  title 'SSMC web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.

'
  desc 'check', 'Verify that SSMC generates log records for system access by doing the following:

1. Log on to SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following commands:

a. $ sudo /ssmc/bin/config_security.sh -o  tcp_access_log -a status
TCP access logging is enabled

If the command output does not read "TCP access logging is enabled", this is a finding.

b. $ sudo /ssmc/bin/config_security.sh -o  http_access_log -f -a status
HTTP access logging is enabled

If the command output does not read "HTTP access logging is enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to generate log records for system access by doing the following:

1. Log on to SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following commands:

$ sudo /ssmc/bin/config_security.sh -f -o  tcp_access_log -a enable

$ sudo /ssmc/bin/config_security.sh -f -o  http_access_log -f -a enable'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58880r869968_chk'
  tag severity: 'medium'
  tag gid: 'V-255267'
  tag rid: 'SV-255267r869970_rule'
  tag stig_id: 'SSMC-WS-030020'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-58824r869969_fix'
  tag satisfies: ['SRG-APP-000089-WSR-000047', 'SRG-APP-000093-WSR-000053', 'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000092-WSR-000055']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000169', 'CCI-001462', 'CCI-001464']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 a', 'AU-14 (2)', 'AU-14 (1)']
end
