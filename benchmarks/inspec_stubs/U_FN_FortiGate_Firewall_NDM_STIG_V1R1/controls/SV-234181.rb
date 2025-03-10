control 'SV-234181' do
  title 'The FortiGate device must off-load audit records on to a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Remote Logging and Archiving.
4. Verify FortiAnalyzer/FortiManager is configured with appropriate IP address.
5. Verify Send logs to syslog is configured with appropriate IP address.

If FortiGate is not logging to disk and at least two central audit servers, this is a finding.

or

Open a CLI console, via SSH or available from the GUI.:

1. Run the following commands:

     # show full-configuration log fortianalyzer setting | grep  server
     # show full-configuration log fortianalyzer2 setting | grep  server
     # show full-configuration log fortianalyzer3 setting | grep  server
     # show full-configuration log syslogd setting | grep  server
     # show full-configuration log syslogd2 setting | grep  server
     # show full-configuration log syslogd3 setting | grep  server
     # show full-configuration log syslogd4 setting | grep  server

If FortiGate is not logging to disk and at least two central audit servers, this is a finding.'
  desc 'fix', 'For audit log resilience, it is recommended to log to the local FortiGate disk, and two central audit servers. To configure this, log in to the FortiGate GUI with Super-Admin privilege.
 
1. Click Log and Report.
2. Click Log Settings.

To add a FortiAnalyzer server:
3. Scroll to Remote Logging and Archiving, toggle the Send logs to FortiAnalyzer/FortiManager setting and enter the appropriate IP address.

To add a syslog server:
4. Scroll to Remote Logging and Archiving, toggle the Send logs to syslog setting, and enter the appropriate IP address.
5. Click Apply to save the settings.
 
or
 
1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log fortianalyzer setting
     #    set status enable
     #    set server {IP Address}
     #    set upload-option realtime
     # end
     # config log syslogd setting
     #    set status enable
     #    set server {IP Address}
     #    set mode reliable
     # end
Note: The central audit server can be a FortiAnalyzer, a syslog server, or one of each.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37366r611730_chk'
  tag severity: 'medium'
  tag gid: 'V-234181'
  tag rid: 'SV-234181r628777_rule'
  tag stig_id: 'FGFW-ND-000110'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-37331r611731_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
