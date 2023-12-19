control 'SV-54193' do
  title 'A web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g. source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every logable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.'
  desc 'check', 'Review the deployment configuration to determine if the web server is sitting behind a proxy server. If the web server is not sitting behind a proxy server, this finding is NA.

If the web server is behind a proxy server, review the documentation and deployment configuration to determine if the web server is configured to generate sufficient information to resolve the source, e.g. source IP, of the logged event and not the proxy server.

Request a user access the hosted application through the proxy server and generate logable events, and then review the logs to determine if the source of the event can be established.

If the source of the event cannot be determined, this is a finding.'
  desc 'fix', 'Configure the web server to generate the client source, not the load balancer or proxy server, of each logable event.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48045r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41616'
  tag rid: 'SV-54193r3_rule'
  tag stig_id: 'SRG-APP-000098-WSR-000060'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-47075r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
