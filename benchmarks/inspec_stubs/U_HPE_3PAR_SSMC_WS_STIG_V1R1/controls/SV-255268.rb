control 'SV-255268' do
  title 'SSMC web server must initiate session logging upon start up.'
  desc 'An attacker can compromise a web server during the startup process. If logging is not initiated until all the web server processes are started, key information may be missed and not available during a forensic investigation. To assure all loggable events are captured, the web server must begin logging once the first web server process is initiated.'
  desc 'check', 'Verify that SSMC is configured to generate log records for system startup and shutdown, system access, and system authentication events. To do so, check if auditd facility (session_log) is enabled:

1. Log on as ssmcadmin to ssmc appliance via SSH. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o session_log -a status
Session log is enabled

If the console output does not show the session log function as enabled, this is a finding.'
  desc 'fix', 'Configure SSMC to generate log records for system startup and shutdown, system access, and system authentication events. To do so, enable auditd facility (session_log):

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell from the TUI menu.

2. Execute the following command to enable session logging:

$ sudo /ssmc/bin/config_security.sh -o session_log -a enable'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58881r869971_chk'
  tag severity: 'medium'
  tag gid: 'V-255268'
  tag rid: 'SV-255268r869973_rule'
  tag stig_id: 'SSMC-WS-030040'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag fix_id: 'F-58825r869972_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
