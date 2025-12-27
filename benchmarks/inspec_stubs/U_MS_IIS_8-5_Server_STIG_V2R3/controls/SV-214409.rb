control 'SV-214409' do
  title 'The IIS 8.5 web server must not be both a website server and a proxy server.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.'
  desc 'check', 'Open the IIS 8.5 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 8.5 web server.

If, under the IIS installed features, "Application Request Routing Cache" is not present, this is not a finding.

If, under the IIS installed features, "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, verify whether "Enable proxy" is selected.

If “Enable proxy" is selected under the "Application Request Routing" settings, this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 8.5 web server.

Under the IIS installed features, "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, remove the check from the "Enable proxy" check box.

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15619r310275_chk'
  tag severity: 'medium'
  tag gid: 'V-214409'
  tag rid: 'SV-214409r508658_rule'
  tag stig_id: 'IISW-SV-000119'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-15617r310276_fix'
  tag 'documentable'
  tag legacy: ['SV-91399', 'V-76703']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
