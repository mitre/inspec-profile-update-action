control 'SV-45915' do
  title 'The file integrity tool must be configured to verify ACLs.'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.'
  desc 'check', 'If using an Advanced Intrusion Detection Environment (AIDE), verify that the configuration contains the "ACL" option for all monitored files and directories.

Procedure:
Check for the default location /etc/aide/aide.conf
or:
# find / -name aide.conf

# egrep "[+]?acl" <aide.conf file>
If the option is not present. This is a finding.

If using a different file integrity tool, check the configuration per tool documentation.'
  desc 'fix', %q(If using AIDE, edit the configuration and add the "ACL" option for all monitored files and directories.

If using a different file integrity tool, configure ACL checking per the tool's documentation.)
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43225r1_chk'
  tag severity: 'low'
  tag gid: 'V-22507'
  tag rid: 'SV-45915r1_rule'
  tag stig_id: 'GEN006570'
  tag gtitle: 'GEN006570'
  tag fix_id: 'F-39295r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
