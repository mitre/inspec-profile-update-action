control 'SV-214468' do
  title 'Double encoded URL requests must be prohibited by any IIS 8.5 website.'
  desc 'Request filtering enables administrators to create a more granular rule set with which to allow or reject inbound web content. By setting limits on web requests, it ensures availability of web services and mitigates the risk of buffer overflow type attacks. When the “Allow double escaping” option is disabled it prevents attacks that rely on double-encoded requests.'
  desc 'check', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click on the site name.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

If the "Allow double escaping" check box is checked, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

Uncheck the "Allow double escaping" check box.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15677r903092_chk'
  tag severity: 'medium'
  tag gid: 'V-214468'
  tag rid: 'SV-214468r903093_rule'
  tag stig_id: 'IISW-SI-000229'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-15675r310609_fix'
  tag 'documentable'
  tag legacy: ['SV-91521', 'V-76825']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
