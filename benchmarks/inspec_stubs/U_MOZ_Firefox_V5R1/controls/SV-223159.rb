control 'SV-223159' do
  title 'FireFox plug-in for ActiveX controls is installed.'
  desc 'When an ActiveX control is referenced in an HTML document, MS Windows checks to see if
the control already resides on the client machine. If not, the control can be downloaded from a
remote web site. This provides an automated delivery method for mobile code.'
  desc 'check', 'Open a browser window, type "about:plugins" in the address bar.

Criteria: If the Mozilla ActiveX control and plugin support is present and enabled, then this is a finding.'
  desc 'fix', 'Remove/uninstall the Mozilla ActiveX plugin'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24832r531294_chk'
  tag severity: 'medium'
  tag gid: 'V-223159'
  tag rid: 'SV-223159r612236_rule'
  tag stig_id: 'DTBF120'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24820r531295_fix'
  tag 'documentable'
  tag legacy: ['SV-16712', 'V-15773']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
