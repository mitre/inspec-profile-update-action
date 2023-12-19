control 'SV-218794' do
  title 'The IIS 10.0 web server must not be both a website server and a proxy server.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that also proxy requests into an otherwise protected network is a common attack, making the attack anonymous.'
  desc 'check', 'Open the IIS 10.0 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.

If, under the IIS installed features, "Application Request Routing Cache" is not present, this is not a finding.

If, under the IIS installed features, "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, verify whether "Enable proxy" is selected.

If “Enable proxy" is selected under the "Application Request Routing" settings, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.

Under the IIS installed features, "Application Request Routing Cache" is present, double-click the icon to open the feature.

From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".

In the "Application Request Routing" settings window, remove the check from the "Enable proxy" check box.

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20266r310857_chk'
  tag severity: 'medium'
  tag gid: 'V-218794'
  tag rid: 'SV-218794r879587_rule'
  tag stig_id: 'IIST-SV-000119'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-20264r310858_fix'
  tag 'documentable'
  tag legacy: ['SV-109227', 'V-100123']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
