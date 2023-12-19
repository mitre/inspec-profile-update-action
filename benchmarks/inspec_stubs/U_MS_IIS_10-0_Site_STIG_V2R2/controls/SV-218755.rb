control 'SV-218755' do
  title 'The IIS 10.0 websites Maximum Query String limit must be configured.'
  desc 'Setting limits on web requests helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks. The Maximum Query String Request Filter describes the upper limit on allowable query string lengths. Upon exceeding the configured value, IIS will generate a Status Code 404.15.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "Request Filtering" icon.

Click “Edit Feature Settings” in the "Actions" pane.

If the "Maximum Query String" value is not set to "2048" or less, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

Set the "Maximum Query String" value to "2048" or less.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20228r311163_chk'
  tag severity: 'medium'
  tag gid: 'V-218755'
  tag rid: 'SV-218755r558649_rule'
  tag stig_id: 'IIST-SI-000227'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-20226r311164_fix'
  tag 'documentable'
  tag legacy: ['SV-109335', 'V-100231']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
