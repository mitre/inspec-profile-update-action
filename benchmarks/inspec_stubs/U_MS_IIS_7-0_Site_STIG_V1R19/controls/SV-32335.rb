control 'SV-32335' do
  title 'Unapproved script mappings in IIS 7 must be removed.'
  desc 'IIS 7 will either allow or deny script execution based on file extension. The ability to control script execution is controlled through two features with IIS 7, Request Filtering and Handler Mappings.

For Handler Mappings, the ISSO must document and approve all allowable file extensions the web site allows (white list) and denies (black list) by the web-site. The white list and black list will be compared to the Handler Mappings in IIS 7. Handler Mappings at the site level take precedence over Handler Mappings at the server level.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click on Handler Mappings.

If any file extensions on the black list are configured with a Handler Mapping, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click on Handler Mappings.
4. Remove any file extensions which are listed on the black list and for which a Handler Mapping has been configured.'
  impact 0.7
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32741r2_chk'
  tag severity: 'high'
  tag gid: 'V-2267'
  tag rid: 'SV-32335r4_rule'
  tag stig_id: 'WA000-WI050 IIS7'
  tag gtitle: 'WA000-WI050'
  tag fix_id: 'F-28820r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
