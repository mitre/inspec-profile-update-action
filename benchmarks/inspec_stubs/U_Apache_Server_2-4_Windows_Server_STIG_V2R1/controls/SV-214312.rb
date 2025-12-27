control 'SV-214312' do
  title 'An Apache web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'Apache web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis. Correctly determining the source will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if the event compromised other assets within the enterprise.

Without sufficient information establishing the source of the logged event, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes but is not limited to time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, and flow control rules invoked.'
  desc 'check', 'Interview the System Administrator to review the configuration of the Apache web server architecture and determine if inbound web traffic is passed through a proxy.

If the Apache web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

View Apache log files as configured in "httpd.conf" files.

When the log file is displayed, review source IP information in log entries and verify the entries do not reflect the IP address of the proxy server.

If the log entries in the log file(s) reflect the IP address of the proxy server as the source, this is a finding.'
  desc 'fix', 'Access the proxy server through which inbound web traffic is passed and configure settings to pass web traffic to the Apache web server transparently.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15524r277439_chk'
  tag severity: 'medium'
  tag gid: 'V-214312'
  tag rid: 'SV-214312r505936_rule'
  tag stig_id: 'AS24-W1-000130'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-15522r277440_fix'
  tag 'documentable'
  tag legacy: ['SV-102439', 'V-92351']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
