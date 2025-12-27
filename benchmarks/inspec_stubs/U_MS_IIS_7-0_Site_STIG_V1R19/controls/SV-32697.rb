control 'SV-32697' do
  title 'The production web-site must filter unlisted file extensions in URL requests.'
  desc 'Request filtering enables administrators to create a more granular rule set to allow or reject inbound web content.   By setting limits on web requests it helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks.  The allow unlisted property of the File Extensions Request Filter enables rejection of requests containing specific file extensions not defined in the File Extensions filter.  Tripping this filter will cause IIS to generate a Status Code 404.7.'
  desc 'check', 'For each site reviewed: 
1. Open the IIS Manager.
2. Click on the site name.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.

If allow unlisted file extensions checkbox is checked, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
5. Uncheck the allow unlisted file extensions checkbox.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26046'
  tag rid: 'SV-32697r2_rule'
  tag stig_id: 'WA000-WI6260'
  tag gtitle: 'WA000-WI6260'
  tag fix_id: 'F-29040r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
