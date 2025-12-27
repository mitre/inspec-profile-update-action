control 'SV-234140' do
  title 'In the event that communication with the central audit server is lost, the FortiGate firewall must continue to queue traffic log records locally.'
  desc 'It is critical that when the network element is at risk of failing to process traffic logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.

In accordance with DoD policy, the traffic log must be sent to a central audit server. When logging functions are lost, system processing cannot be shut down because firewall availability is an overriding concern given the role of the firewall in the enterprise. The system should either be configured to log events to an alternative server or queue log records locally. Upon restoration of the connection to the central audit server, action should be taken to synchronize the local log data with the central audit server.

If the central audit server uses User Datagram Protocol (UDP) communications instead of a connection-oriented protocol such as TCP, a method for detecting a lost connection must be implemented.'
  desc 'check', %q(Verify at least two logging options are configured. It can be any combination of local and/or remote logging.

Via the GUI:

Login via the FortiGate GUI with super-admin privileges. 

- Navigate to Log and Report.
- Navigate to Log Settings.
- Verify the FortiGate Local Log disk settings.
- Verify the Remote and Archiving settings.

or

Via the CLI:

Open a CLI console via SSH or from the "CLI Console" button in the GUI.

Run the following commands to verify which logging settings are enabled:

# show full-configuration log disk setting | grep -i 'status\|diskfull'
- The output should indicate enabled.

# show full-configuration log fortianalyzer setting | grep -i 'status\|server'
# show full-configuration log fortianalyzer2 setting | grep -i 'status\|server'
# show full-configuration log fortianalyzer3 setting | grep -i 'status\|server'
# show full-configuration log syslogd setting | grep -i 'status\|server'
# show full-configuration log syslogd2 setting | grep -i 'status\|server'
# show full-configuration log syslogd3 setting | grep -i 'status\|server'
# show full-configuration log syslogd4 setting | grep -i 'status\|server'
- The output should indicate enabled and an IP address.

If the FortiGate is not logging to at least two locations (local and remote OR remote(x2) only), this is a finding.)
  desc 'fix', 'For audit log resilience, it is required to log to the local FortiGate disk and a central audit server, or two central audit servers. To do this, log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. For Local Log setting options, toggle the Disk setting to right.

To add a syslog server:
5. For Remote Logging and Archiving, toggle the Send logs to syslog setting and enter the appropriate IP address.
6. Click Apply to save the settings.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log disk setting
     #    set status enable
     #    set diskfull overwrite
     # end
     # config log syslogd setting
     #    set status enable
     #    set server {IP Address}
     #    set mode reliable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37325r863249_chk'
  tag severity: 'medium'
  tag gid: 'V-234140'
  tag rid: 'SV-234140r863251_rule'
  tag stig_id: 'FNFG-FW-000045'
  tag gtitle: 'SRG-NET-000089-FW-000019'
  tag fix_id: 'F-37290r863250_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
