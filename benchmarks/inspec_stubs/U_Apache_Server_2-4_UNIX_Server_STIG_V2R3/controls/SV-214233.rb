control 'SV-214233' do
  title 'An Apache web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'Apache web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct source of the events (e.g., source IP) is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every logable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.'
  desc 'check', %q(If Apache server is not behind a load balancer or proxy server, this check is Not Applicable.

Interview the System Administrator to review the configuration of the Apache web server architecture and determine if inbound web traffic is passed through a proxy.

If the Apache web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Review the location of the log files.

When the log file is displayed, review the source IP information in the log entries and verify the entries do not reflect the IP address of the proxy server.
If the log entries in the log file(s) reflect the IP address of the client in addition to the proxy address, this is not a finding.
If the log entries in the log file(s) reflect the IP address of the proxy server as the source, this is a finding.

If logs containing source/destination IPs can be obtained at the load balancer/proxy server, this is not a finding.)
  desc 'fix', 'Access the proxy server through which inbound web traffic is passed and configure settings to pass web traffic to the Apache web server transparently.

Refer to https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html for additional information on logging options based on your proxy/load balancing setup.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15447r505079_chk'
  tag severity: 'medium'
  tag gid: 'V-214233'
  tag rid: 'SV-214233r612240_rule'
  tag stig_id: 'AS24-U1-000130'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-15445r505080_fix'
  tag 'documentable'
  tag legacy: ['SV-102709', 'V-92621']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
