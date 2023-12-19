control 'SV-26861' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27831r2_chk'
  tag severity: 'low'
  tag gid: 'V-22509'
  tag rid: 'SV-26861r1_rule'
  tag stig_id: 'GEN006575'
  tag gtitle: 'GEN006575'
  tag fix_id: 'F-24103r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
