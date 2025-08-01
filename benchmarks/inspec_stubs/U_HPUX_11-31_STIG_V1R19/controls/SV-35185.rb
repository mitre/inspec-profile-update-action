control 'SV-35185' do
  title 'The file integrity tool must be configured to verify ACLs.'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.'
  desc 'check', %q(Ask the SA if the file integrity tool is configured to monitor directories and files for ACL settings. If using the Advanced Intrusion Detection Environment (AIDE) tool, verify the configuration file (aide.conf) contains the ACL option for all monitored files and directories. See the following example.

# find / -type f -name aide.conf | xargs -n1 ls -lL

# cat <path>/aide.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' |grep -v "^#" | \
egrep -i "^acl = |acl"

If the option is not present, this is a finding.

If using a different file integrity tool, check the configuration per tool the vendor's documentation.)
  desc 'fix', "If using AIDE, edit the configuration and add the ACL option for all monitored files and directories.

If using a different file integrity tool, configure ACL checking per the tool vendor's documentation."
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35029r1_chk'
  tag severity: 'low'
  tag gid: 'V-22507'
  tag rid: 'SV-35185r1_rule'
  tag stig_id: 'GEN006570'
  tag gtitle: 'GEN006570'
  tag fix_id: 'F-30321r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
