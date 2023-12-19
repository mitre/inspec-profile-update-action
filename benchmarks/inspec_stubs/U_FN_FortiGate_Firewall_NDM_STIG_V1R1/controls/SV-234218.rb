control 'SV-234218' do
  title 'The FortiGate device must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can be used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, is important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', "Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Verify FortiGate is set to log to Disk, log to FortiAnalyzer, and log to syslog.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following commands:
# show full-configuration log disk setting | grep -i  'status\\|diskfull' 
# show full-configuration log fortianalyzer setting | grep  server
# show full-configuration log fortianalyzer2 setting | grep  server
# show full-configuration log fortianalyzer3 setting | grep  server
# show full-configuration log syslogd setting | grep  server
# show full-configuration log syslogd2 setting | grep  server
# show full-configuration log syslogd3 setting | grep  server
# show full-configuration log syslogd4 setting | grep  server

If the FortiGate is not logging to disk and at least two central audit servers, this is a finding."
  desc 'fix', 'For audit log resilience, it is recommended to log to the local FortiGate disk, and two central audit servers. To configure this, log in to the FortiGate GUI with Super-Admin privilege.
 
1. Click Log and Report.
2. Click Log Settings.
3. For Local Log setting options, toggle the Disk setting to right.

To add a FortiAnalyzer server:
4. Scroll to Remote Logging and Archiving, toggle the Send logs to FortiAnalyzer/FortiManager setting, and then enter the appropriate IP address.

To add a syslog server:
5. Scroll to Remote Logging and Archiving, toggle the Send logs to syslog setting, and then enter the appropriate IP address.
6. Click Apply to save the settings.
 
or
 
1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
# config log disk setting
#    set status enable
#    set diskfull overwrite
# end
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
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37403r611841_chk'
  tag severity: 'high'
  tag gid: 'V-234218'
  tag rid: 'SV-234218r628777_rule'
  tag stig_id: 'FGFW-ND-000295'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-37368r611842_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
