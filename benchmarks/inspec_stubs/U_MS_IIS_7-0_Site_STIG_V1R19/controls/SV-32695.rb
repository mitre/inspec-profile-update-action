control 'SV-32695' do
  title 'The web-site must not allow non-ASCII characters in URLs.'
  desc 'By setting limits on web requests, it ensures availability of web services and mitigates the risk of buffer overflow type attacks.  The allow high-bit characters Request Filter enables rejection of requests containing non-ASCII characters.'
  desc 'check', 'For each site reviewed: 
1. Open the IIS Manager.
2. Click on the site name.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.

If the allow high-bit characters checkbox is checked, this is a finding.

NOTE:  If the site has operational reasons to set allow high-bit characters to checked, this vulnerability can be documented locally by the ISSM/ISSO.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
5. Uncheck the allow high-bit characters checkbox.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32892r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26044'
  tag rid: 'SV-32695r4_rule'
  tag stig_id: 'WA000-WI6240'
  tag gtitle: 'WA000-WI6240'
  tag fix_id: 'F-29038r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
