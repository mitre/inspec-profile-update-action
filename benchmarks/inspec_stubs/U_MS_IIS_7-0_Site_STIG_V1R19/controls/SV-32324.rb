control 'SV-32324' do
  title 'Each readable web document directory must contain a default, home, index, or equivalent document.'
  desc 'The goal is to control the web users experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end. Also, enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server’s directory structure by locating directories with default pages. This practice helps ensure the anonymous web user will not obtain directory browsing information or an error message revealing the server type and version.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click Default Document.
4. In the Actions Pane, verify the Default Document feature is enabled. If not, this is a finding.
5. Review the document types. 
6. Click the Content View tab and ensure there is a document of that type in the directory. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click Default Document.
4. In the Action pane select Enable.
5. Click the Content View tab and ensure there is a document of that type in the directory.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32731r1_chk'
  tag severity: 'low'
  tag gid: 'V-2245'
  tag rid: 'SV-32324r2_rule'
  tag stig_id: 'WG170 IIS7'
  tag gtitle: 'WG170'
  tag fix_id: 'F-29061r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
