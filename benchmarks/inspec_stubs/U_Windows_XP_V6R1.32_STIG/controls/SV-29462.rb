control 'SV-29462' do
  title 'Remove Software Certificate Installation Files'
  desc 'This check verifies that software certificate installation files have been removed from a system.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, then this is a finding.

Documentable Explanation:  This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).  Some applications create files with extensions of .p12 that are NOT certificate installation files.  Removal from systems of non-certificate installation files are not required.  These should be documented with the IAO.'
  desc 'fix', 'Remove any certificate installation files found on a system.

Note:  This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager)'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-16140r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15823'
  tag rid: 'SV-29462r1_rule'
  tag gtitle: 'Software Certificate Installation Files'
  tag fix_id: 'F-15775r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
