control 'SV-234149' do
  title 'The FortiGate firewall must send traffic log entries to a central audit server for management and configuration of the traffic log entries.'
  desc 'Without the ability to centrally manage the content captured in the traffic log entries, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized traffic log management must have the ability to support centralized management. The content captured in traffic log entries must be managed from a central location (necessitating automation). Centralized management of traffic log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. 

Ensure at least one syslog server is configured on the firewall.

If the product inherently has the ability to store log records locally, the local log must also be secured. However, this requirement is not met since it calls for a use of a central audit server.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Under Remote Logging and Archiving, verify FortiAnalyzer and/or syslog settings are enabled and configured with IP addresses of central FortiAnalyzer or Syslog server(s).

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log syslogd setting | grep -i status
 Check output for: 
          set status enable
3. Run the following command:
      # show full-configuration log fortianalyzer setting | grep -i status
    check output for: 
          set status enable

If the FortiGate is not configured to send traffic logs to a central audit server, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Go to Remote Logging and Archiving.

If using FortiAnalyzer:
4. Toggle Send logs to FortiAnalyzer/FortiManager to the right.
5. Configure FortiAnalyzer/FortiManager with designated IP address.
6. Configure Upload Option, SSL encrypt log transmission and Allow access to FortiGate REST API per the organizational requirement.

If using a central syslog server:
7. Toggle Send logs to syslog to the right.
8. Configure syslog settings with designated IP Address/FQDN.
9. Click Apply.

or

Log in to the FortiGate GUI with Super-Admin privilege.

Open a CLI console, via SSH or available from the GUI.

If using FortiAnalyzer, run the following command:
     # config log fortianalyzer setting
     #    set status enable
     #    set server {IP address}
     # end

If using central syslog Server, run the following command:
     # config log syslogd setting
     #    set status enable
     #    set server {IP address}
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37334r611445_chk'
  tag severity: 'medium'
  tag gid: 'V-234149'
  tag rid: 'SV-234149r863248_rule'
  tag stig_id: 'FNFG-FW-000100'
  tag gtitle: 'SRG-NET-000333-FW-000014'
  tag fix_id: 'F-37299r835166_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
