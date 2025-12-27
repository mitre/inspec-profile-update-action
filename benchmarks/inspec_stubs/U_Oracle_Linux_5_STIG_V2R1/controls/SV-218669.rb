control 'SV-218669' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20144r562918_chk'
  tag severity: 'low'
  tag gid: 'V-218669'
  tag rid: 'SV-218669r603259_rule'
  tag stig_id: 'GEN006571'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-20142r562919_fix'
  tag 'documentable'
  tag legacy: ['V-22508', 'SV-63631']
  tag cci: ['CCI-001297', 'CCI-002696']
  tag nist: ['SI-7', 'SI-6 a']
end
