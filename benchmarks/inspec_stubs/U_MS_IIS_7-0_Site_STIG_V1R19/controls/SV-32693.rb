control 'SV-32693' do
  title 'The production web-site must limit the MaxURL.'
  desc 'Request filtering replaces URLScan in IIS, enabling administrators to create a more granular rule set with which to allow or reject inbound web content.   By setting limits on web requests, it helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks.  The MaxURL Request Filter limits the number of bytes the server will accept in a URL.'
  desc 'check', 'For each site reviewed: 
1. Open the IIS Manager.
2. Click on the site name.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.

If the maxURL value is not set to 4096, this is a finding.

NOTE: If the site has operational reasons to set maxURL to an alternate value, and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
5. Set the maxURL value to 4096.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32890r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26042'
  tag rid: 'SV-32693r3_rule'
  tag stig_id: 'WA000-WI6220'
  tag gtitle: 'WA000-WI6220'
  tag fix_id: 'F-29036r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
