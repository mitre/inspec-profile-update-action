control 'SV-35190' do
  title 'The file integrity tool must be configured to verify extended attributes.'
  desc 'Extended attributes in file systems are used to contain arbitrary data and file metadata with possible security implications.'
  desc 'check', %q(Ask the SA if the file integrity tool is configured to monitor directories and files for xattrs settings. If using the Advanced Intrusion Detection Environment (AIDE) tool, verify the configuration file (aide.conf) contains the xattrs option for all monitored files and directories. See the following example.
# find / -type f -name aide.conf | xargs -n1 ls -lL
# cat <path>/aide.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' |grep -v "^#" | \
egrep -i "^xattrs = |xattrs"

If the option is not present, this is a finding.

If using a different file integrity tool, check the configuration per the tool vendor's documentation.)
  desc 'fix', "If using AIDE, edit the configuration and add the xattrs option for all monitored files and directories.

If using a different file integrity tool, configure extended attributes checking per the tool's documentation."
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35035r1_chk'
  tag severity: 'low'
  tag gid: 'V-22508'
  tag rid: 'SV-35190r1_rule'
  tag stig_id: 'GEN006571'
  tag gtitle: 'GEN006571'
  tag fix_id: 'F-30326r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
