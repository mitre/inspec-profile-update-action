control 'SV-218368' do
  title 'The owner, group-owner, mode, ACL and location of files with the setgid bit set must be documented using site-defined procedures.'
  desc 'All files with the setgid bit set will allow anyone running these files to be temporarily assigned the GID of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs allowing reading and writing of files, or shell escapes.'
  desc 'check', 'If STIGID GEN000220 is satisfied, this is not a finding.

List all setgid files on the system.
Procedure:

# find / -perm -2000 -exec ls -l {} \\; | more

Note: Executing these commands may result in large listings of files; the output may be redirected to a file for easier analysis.

Ask the SA or IAO if files with the setgid bit set have been documented. Documentation must include owner, group-owner, mode, ACL, and location.

If any undocumented file has its setgid bit set, this is a finding.

If a tool is being run then the configuration file for the appropriate tool needs to be checked for selection lines /bin, /sbin, /lib, and /usr.

If a file integrity tool is set to check setuid and setgid, this is not a finding.'
  desc 'fix', 'Document the files with the sgid bit set or unset the sgid bit on the executable.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19843r569062_chk'
  tag severity: 'medium'
  tag gid: 'V-218368'
  tag rid: 'SV-218368r603259_rule'
  tag stig_id: 'GEN002440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19841r569063_fix'
  tag 'documentable'
  tag legacy: ['V-802', 'SV-63459']
  tag cci: ['CCI-000366', 'CCI-000368']
  tag nist: ['CM-6 b', 'CM-6 c']
end
