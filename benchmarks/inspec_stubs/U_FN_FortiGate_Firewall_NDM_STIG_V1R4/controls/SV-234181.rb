control 'SV-234181' do
  title 'The FortiGate device must off-load audit records on to a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', %q(Verify remote logging is configured.

Via the GUI:

Login via the FortiGate GUI with super-admin privileges. 

- Navigate to Log and Report.
- Navigate to Log Settings.
- Verify the Remote and Archiving settings.

or

Via the CLI:

Open a CLI console via SSH or from the "CLI Console" button in the GUI.

Run the following commands to verify which logging settings are enabled:

# show full-configuration log fortianalyzer setting | grep -i 'status\|server'
# show full-configuration log fortianalyzer2 setting | grep -i 'status\|server'
# show full-configuration log fortianalyzer3 setting | grep -i 'status\|server'
# show full-configuration log syslogd setting | grep -i 'status\|server'
# show full-configuration log syslogd2 setting | grep -i 'status\|server'
# show full-configuration log syslogd3 setting | grep -i 'status\|server'
# show full-configuration log syslogd4 setting | grep -i 'status\|server'
- The output should indicate enabled and an IP address.

If the FortiGate is not logging to a fortianalyzer or syslog server, this is a finding.)
  desc 'fix', 'Login via the GUI with super-admin privileges.

1. Click Log and Report.
2. Click Log Settings.

To add a FortiAnalyzer:
- In the Remote Logging and Archiving, enable logging to FortiAnalyzer and provide the IP address.

To add a Syslog server:
- In the Remote Logging and Archiving, enable Send logs to Syslog and provide the IP address.

3. Apply changes.

or

1. Open a CLI console via SSH or from the "CLI Console" button in the GUI.

2. Configure a fortianalyzer or syslog server with the following commands:

FortiAnalyzer:
# config log fortianalyzer setting
#    set status enable
#    set server {IP Address}
#    set upload-option realtime
# end

Syslog:
# config log syslogd setting
#    set status enable
#    set server {IP Address}
#    set mode reliable
# end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37366r863252_chk'
  tag severity: 'medium'
  tag gid: 'V-234181'
  tag rid: 'SV-234181r879886_rule'
  tag stig_id: 'FGFW-ND-000110'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-37331r863253_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
