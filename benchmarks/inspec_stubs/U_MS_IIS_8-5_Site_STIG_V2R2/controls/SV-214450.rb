control 'SV-214450' do
  title 'An IIS 8.5 website behind a load balancer or proxy server, must produce log records containing the source client IP and destination information.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g. source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every logable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.'
  desc 'check', 'Interview the System Administrator to review the configuration of the IIS 8.5 architecture and determine if inbound web traffic is passed through a proxy.

If the IIS 8.5 is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name.

Click the "Logging" icon.

Click on "View log file" button.

When log file is displaced, review source IP information in log entries and verify entries do not reflect the IP address of the proxy server.

If the website is not behind a load balancer or proxy server, this is Not Applicable.

If the log entries in the log file(s) reflect the IP address of the proxy server as the source, this is a finding.

If provisions have been made to log the client IP via another field (i.e., utilizing X-Forwarded-For), this is not a finding.'
  desc 'fix', 'Access the proxy server through which inbound web traffic is passed and configure settings to pass web traffic to the IIS 8.5 web server transparently.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15659r310554_chk'
  tag severity: 'medium'
  tag gid: 'V-214450'
  tag rid: 'SV-214450r508659_rule'
  tag stig_id: 'IISW-SI-000208'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-15657r310555_fix'
  tag 'documentable'
  tag legacy: ['SV-91483', 'V-76787']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
