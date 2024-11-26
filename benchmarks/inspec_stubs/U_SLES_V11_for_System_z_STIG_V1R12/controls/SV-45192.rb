control 'SV-45192' do
  title 'The owner, group-owner, mode, ACL and location of files with the setgid bit set must be documented using site-defined procedures.'
  desc 'All files with the setgid bit set will allow anyone running these files to be temporarily assigned the GID of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs allowing reading and writing of files, or shell escapes.'
  desc 'check', 'List all setgid files on the system.
Procedure:
# find / -perm -2000 -exec ls -l {} \\; | more

Note: Executing these commands may result in large listings of files; the output may be redirected to a file for easier analysis.

Ask the SA or IAO if files with the sgid bit set have been documented. If any undocumented file has its sgid bit set, this is a finding.'
  desc 'fix', 'Document the files with the sgid bit set or unset the sgid bit on the executable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-802'
  tag rid: 'SV-45192r1_rule'
  tag stig_id: 'GEN002440'
  tag gtitle: 'GEN002440'
  tag fix_id: 'F-38587r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000368']
  tag nist: ['CM-6 c']
end
