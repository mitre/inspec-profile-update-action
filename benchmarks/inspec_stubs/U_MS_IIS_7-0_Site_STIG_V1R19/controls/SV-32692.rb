control 'SV-32692' do
  title 'The web-site must limit the number of bytes accepted in a request.'
  desc 'By setting limits on web requests, it ensures availability of web services and mitigates the risk of buffer overflow type attacks.  The maxAllowedContentLength Request Filter limits the number of bytes the server will accept in a request.'
  desc 'check', 'For each site reviewed: 
1. Open the IIS Manager.
2. Click on the site name.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.

If the maxAllowedContentLength value is not set to 30000000, this is a finding.

NOTE: If the site has operational reasons to set maxAllowedContentLength to an alternate value, and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
5. Set the maxAllowedContentLength value to 30000000.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32889r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26041'
  tag rid: 'SV-32692r3_rule'
  tag stig_id: 'WA000-WI6210'
  tag gtitle: 'WA000-WI6210'
  tag fix_id: 'F-29035r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
