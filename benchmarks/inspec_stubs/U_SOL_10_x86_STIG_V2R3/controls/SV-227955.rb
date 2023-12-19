control 'SV-227955' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30117r490291_chk'
  tag severity: 'low'
  tag gid: 'V-227955'
  tag rid: 'SV-227955r603266_rule'
  tag stig_id: 'GEN006575'
  tag gtitle: 'SRG-OS-000278'
  tag fix_id: 'F-30105r490292_fix'
  tag 'documentable'
  tag legacy: ['V-22509', 'SV-26861']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
