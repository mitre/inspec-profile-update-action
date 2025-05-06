control 'SV-37753' do
  title 'The file integrity tool must be configured to verify extended attributes.'
  desc 'Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.'
  desc 'check', 'If using an Advanced Intrusion Detection Environment (AIDE), verify the configuration contains the "xattrs" option for all monitored files and directories.

Procedure:
Check for the default location /etc/aide/aide.conf
or:
# find / -name aide.conf

# egrep "[+]?xattrs" <aide.conf file>
If the option is not present. This is a finding.
If using a different file integrity tool, check the configuration per tool documentation.'
  desc 'fix', %q(If using AIDE, edit the configuration and add the "xattrs" option for all monitored files and directories.

If using a different file integrity tool, configure extended attributes checking per the tool's documentation.)
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36951r1_chk'
  tag severity: 'low'
  tag gid: 'V-22508'
  tag rid: 'SV-37753r1_rule'
  tag stig_id: 'GEN006571'
  tag gtitle: 'GEN006571'
  tag fix_id: 'F-32215r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
