control 'SV-32380' do
  title 'A private web-sites authentication mechanism must use client certificates.'
  desc 'A DoD private web-site must utilize PKI as an authentication mechanism for web users. Information systems residing behind web servers requiring authorization based on individual identity shall use the identity provided by certificate-based authentication to support access control decisions. Not using client certificates allows an attacker unauthenticated access to private web-sites.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double click the SSL Settings icon.
4. Ensure Clients Certificate Required is checked. If not, this is a finding.

NOTE: If the site has operational reasons to set Clients Certificate Required to unchecked, this vulnerability can be documented locally by the ISSM/ISSO.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double click the SSL Settings icon.
4. Click Clients Certificate Required button.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32933r3_chk'
  tag severity: 'medium'
  tag gid: 'V-6531'
  tag rid: 'SV-32380r4_rule'
  tag stig_id: 'WG140 IIS7'
  tag gtitle: 'WG140'
  tag fix_id: 'F-28970r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
