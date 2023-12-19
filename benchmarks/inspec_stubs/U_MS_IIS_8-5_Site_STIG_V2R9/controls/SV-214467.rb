control 'SV-214467' do
  title 'Non-ASCII characters in URLs must be prohibited by any IIS 8.5 website.'
  desc 'By setting limits on web requests, it ensures availability of web services and mitigates the risk of buffer overflow type attacks. The allow high-bit characters Request Filter enables rejection of requests containing non-ASCII characters.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click on the site name.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

If the "Allow high-bit characters" check box is checked, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name under review.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

Uncheck the "Allow high-bit characters" check box.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15676r310605_chk'
  tag severity: 'medium'
  tag gid: 'V-214467'
  tag rid: 'SV-214467r879650_rule'
  tag stig_id: 'IISW-SI-000228'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-15674r310606_fix'
  tag 'documentable'
  tag legacy: ['SV-91519', 'V-76823']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
