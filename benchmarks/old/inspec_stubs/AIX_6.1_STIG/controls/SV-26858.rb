control 'SV-26858' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27829r2_chk'
  tag severity: 'low'
  tag gid: 'V-22507'
  tag rid: 'SV-26858r1_rule'
  tag stig_id: 'GEN006570'
  tag gtitle: 'GEN006570'
  tag fix_id: 'F-24101r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
