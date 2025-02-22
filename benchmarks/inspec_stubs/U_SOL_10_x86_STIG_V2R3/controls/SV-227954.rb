control 'SV-227954' do
  title 'The file integrity tool must be configured to verify extended attributes.'
  desc 'Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.'
  desc 'check', 'If using AIDE, verify the configuration contains the xattrs option for all monitored files and directories.  Here is an example AIDE configuration fragment.

SampleRule = p+i+l+n+u+g+s+m+c+acl+xattrs+sha256
/bin SampleRule

If the xattrs option is not present, this is a finding.

If using a different file integrity tool, check the configuration per tool documentation.'
  desc 'fix', "If using AIDE, edit the configuration and add the xattrs option for all monitored files and directories.

If using a different file integrity tool, configure extended attributes checking per the tool's documentation."
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30116r490288_chk'
  tag severity: 'low'
  tag gid: 'V-227954'
  tag rid: 'SV-227954r854520_rule'
  tag stig_id: 'GEN006571'
  tag gtitle: 'SRG-OS-000445'
  tag fix_id: 'F-30104r490289_fix'
  tag 'documentable'
  tag legacy: ['V-22508', 'SV-26860']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
