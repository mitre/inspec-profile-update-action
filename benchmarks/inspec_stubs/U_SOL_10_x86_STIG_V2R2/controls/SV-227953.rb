control 'SV-227953' do
  title 'The file integrity tool must be configured to verify ACLs.'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.'
  desc 'check', 'If using AIDE, verify the configuration contains the acl option for all monitored files and directories.  Here is an example AIDE configuration fragment.

SampleRule = p+i+l+n+u+g+s+m+c+acl+xattrs+sha256
/bin SampleRule

If the acl option is not present, this is a finding.

If using a different file integrity tool, check the configuration per tool documentation.'
  desc 'fix', "If using AIDE, edit the configuration and add the acl option for all monitored files and directories.

If using a different file integrity tool, configure ACL checking per the tool's documentation."
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30115r490285_chk'
  tag severity: 'low'
  tag gid: 'V-227953'
  tag rid: 'SV-227953r603266_rule'
  tag stig_id: 'GEN006570'
  tag gtitle: 'SRG-OS-000445'
  tag fix_id: 'F-30103r490286_fix'
  tag 'documentable'
  tag legacy: ['V-22507', 'SV-26858']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
