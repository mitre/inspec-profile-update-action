control 'SV-234218' do
  title 'The FortiGate device must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can be used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, is important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', %q(Verify that FortiGate is configured to send logs to a central log server.  

Log in via the FortiGate GUI with super-admin privileges. 

1. Navigate to Log and Report.
2. Navigate to Log Settings.
3. Locate the Remote Logging and Archiving section.
4. Verify FortiGate is configured to log to a FortiAnalyzer or a syslog server.

or

Open a CLI console via SSH or from the "CLI Console" button in the GUI.

Run the following commands and verify that at least one of the settings reflects "set status enable" in the output:
# show full-configuration | grep -A1 'log fortianalyzer'
# show full-configuration | grep -A1 'log syslogd.* setting'

The CLI output will indicate "set status enable" if configured.

If the FortiGate is not logging to a central log server, this is a finding.)
  desc 'fix', 'Log in via the GUI with super-admin privileges.

1. Click Log and Report.
2. Click Log Settings.
3. Locate the Remote Logging and Archiving section.
4. Configure FortiGate to log to a FortiAnalyzer or syslog server.
- Enable logging to FortiAnalyzer and provide the IP address. Additional FortiAnalyzer logging destinations can be configured in the CLI.
- Enable the "Send logs to syslog" toggle and provide the IP address. Additional syslog logging destinations can be configured in the CLI.
5. Apply changes.

or

1. Open a CLI console via SSH or from the "CLI Console" button in the GUI.
2. Configure a FortiAnalyzer or syslog server with the following commands:

FortiAnalyzer Logging:
config log fortianalyzer setting
   set status enable
   set server {IP Address}
   set upload-option realtime
end

syslog Logging:
config log syslogd setting
   set status enable
   set server {IP Address}
   set mode reliable
end'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37403r917638_chk'
  tag severity: 'high'
  tag gid: 'V-234218'
  tag rid: 'SV-234218r917639_rule'
  tag stig_id: 'FGFW-ND-000295'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-37368r917639_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
