control 'SV-35194' do
  title 'The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents.'
  desc 'File integrity tools often use cryptographic hashes for verifying file contents have not been altered. These hashes must be FIPS 140-2 approved.'
  desc 'check', %q(Ask the SA if the file integrity tool is configured to monitor directories and files for sha256 or sha512 settings. If using the Advanced Intrusion Detection Environment (AIDE) tool, verify the configuration file (aide.conf) contains the xattrs option for all monitored files and directories. See the following example.

# find / -type f -name aide.conf | xargs -n1 ls -lL

# cat <path>/aide.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' |grep -v "^#" | \
egrep -i "sha256|sha512"

If one of these option is not present, this is a finding.

If using a different file integrity tool, check the configuration per tool documentation.)
  desc 'fix', "If using AIDE, edit the configuration and add the sha512 option for all monitored files and directories.

If using a different file integrity tool, configure FIPS 140-2 approved cryptographic hashes per the tool's documentation."
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35039r1_chk'
  tag severity: 'low'
  tag gid: 'V-22509'
  tag rid: 'SV-35194r1_rule'
  tag stig_id: 'GEN006575'
  tag gtitle: 'GEN006575'
  tag fix_id: 'F-30331r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
