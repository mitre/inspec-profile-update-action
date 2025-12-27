control 'SV-214464' do
  title 'The IIS 8.5 website must be configured to limit the maxURL.'
  desc 'Request filtering replaces URLScan in IIS, enabling administrators to create a more granular rule set with which to allow or reject inbound web content. By setting limits on web requests, it helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks. The MaxURL Request Filter limits the number of bytes the server will accept in a URL.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click on the site name.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

If the "maxUrl" value is not set to "4096" or less, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Click the site name under review.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

Set the "maxURL" value to "4096" or less.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15673r310596_chk'
  tag severity: 'medium'
  tag gid: 'V-214464'
  tag rid: 'SV-214464r879650_rule'
  tag stig_id: 'IISW-SI-000225'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-15671r310597_fix'
  tag 'documentable'
  tag legacy: ['SV-91513', 'V-76817']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
