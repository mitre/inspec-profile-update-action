control 'SV-214470' do
  title 'Directory Browsing on the IIS 8.5 website must be disabled.'
  desc 'Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in IIS, users could receive a web page listing the contents of the directory. If directory browsing is enabled the risk of inadvertently disclosing sensitive content is increased.'
  desc 'check', 'Note: If the Directory Browsing feature is not enabled, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Click the Site.

Double-click the "Directory Browsing" icon.

If the "Directory Browsing" is not installed, this is Not Applicable.

Under the "Actions" pane verify "Directory Browsing" is "Disabled".

If "Directory Browsing" is not "Disabled", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the Site.

Double-click the "Directory Browsing" icon.

Under the "Actions" pane click "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15679r505318_chk'
  tag severity: 'medium'
  tag gid: 'V-214470'
  tag rid: 'SV-214470r508659_rule'
  tag stig_id: 'IISW-SI-000231'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-15677r505319_fix'
  tag 'documentable'
  tag legacy: ['SV-91525', 'V-76829']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
