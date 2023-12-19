control 'SV-218808' do
  title 'Directory Browsing on the IIS 10.0 web server must be disabled.'
  desc 'Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in IIS, users could receive a web page listing the contents of the directory. If directory browsing is enabled, the risk of inadvertently disclosing sensitive content is increased.'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Directory Browsing" icon.

Under the “Actions” pane verify "Directory Browsing" is disabled.

If “Directory Browsing” is not disabled, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Directory Browsing" icon.

Under the "Actions" pane click "Disabled".

Under the "Actions" pane, click "Apply".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20280r310899_chk'
  tag severity: 'medium'
  tag gid: 'V-218808'
  tag rid: 'SV-218808r561041_rule'
  tag stig_id: 'IIST-SV-000138'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-20278r310900_fix'
  tag 'documentable'
  tag legacy: ['SV-109255', 'V-100151']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
