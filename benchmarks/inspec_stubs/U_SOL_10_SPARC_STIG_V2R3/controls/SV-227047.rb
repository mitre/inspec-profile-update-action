control 'SV-227047' do
  title 'The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents.'
  desc 'File integrity tools often use cryptographic hashes for verifying that file contents have not been altered.  These hashes must be FIPS 140-2 approved.'
  desc 'check', 'If using AIDE, verify the configuration contains the sha256 or sha512 options for all monitored files and directories.  Here is an example AIDE configuration fragment.

SampleRule = p+i+l+n+u+g+s+m+c+acl+xattrs+sha256
/bin SampleRule

If either the sha256 or sha512 option is not present, this is a finding.

If using a different file integrity tool, check the configuration per tool documentation.'
  desc 'fix', "If using AIDE, edit the configuration and add the sha256 or sha512 option for all monitored files and directories.

If using a different file integrity tool, configure FIPS 140-2 approved cryptographic hashes per the tool's documentation."
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29209r485504_chk'
  tag severity: 'low'
  tag gid: 'V-227047'
  tag rid: 'SV-227047r603265_rule'
  tag stig_id: 'GEN006575'
  tag gtitle: 'SRG-OS-000278'
  tag fix_id: 'F-29197r485505_fix'
  tag 'documentable'
  tag legacy: ['SV-26861', 'V-22509']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
