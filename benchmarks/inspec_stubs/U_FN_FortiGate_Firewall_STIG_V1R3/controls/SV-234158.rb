control 'SV-234158' do
  title 'The FortiGate firewall must generate an alert that can be forwarded to, at a minimum, the Information System Security Officer (ISSO) and Information System Security Manager (ISSM) when denial-of-service (DoS) incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The firewall generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs), which require real-time alerts. These messages should include a severity-level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The firewall must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', "The firewall must be configured to send events to a syslog server. Anomaly events, such as a DoS attack are sent with a severity of critical. The syslog server will notify the ISSO and ISSM. To verify the syslog configuration, log in to the FortiGate GUI with Super-Admin privileges.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log syslogd setting | grep -i  'mode\\|server' 
The output should be:     
     set server {123.123.123.123}
     set mode reliable

To ensure a secure connection, a certificate must be loaded, encryption enabled, and the SSL version set. To verify, while still in the CLI, run the following command:
     # get log syslogd setting
Check for the following:
     set enc-algorithm {MEDIUM-HIGH | HIGH}
     set certificate

If the syslogd is not configured to send logs to a central syslog server, this is a finding."
  desc 'fix', 'Syslog server is used to send alerts for DoS incidents. To enable syslog, log in to the FortiGate GUI with Super-Admin privileges.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log syslogd setting
     #    set status enable
     #    set server {IP address of site syslog server}
     #    set mode {reliable}
     #    set enc-algorithm {high-medium | high}
     #    set port {server listen port}
     #    set facility syslog
     #    set source-ip {source IP address}
     #    set max-log-rate {value between 1 and 100000}
     #    set certificate {certificate string}
     # end'
  impact 0.3
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37343r611472_chk'
  tag severity: 'low'
  tag gid: 'V-234158'
  tag rid: 'SV-234158r852967_rule'
  tag stig_id: 'FNFG-FW-000150'
  tag gtitle: 'SRG-NET-000392-FW-000042'
  tag fix_id: 'F-37308r611473_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
