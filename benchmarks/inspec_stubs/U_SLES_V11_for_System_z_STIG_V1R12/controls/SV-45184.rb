control 'SV-45184' do
  title 'The owner, group-owner, mode, ACL, and location of files with the setuid bit set must be documented using site-defined procedures.'
  desc 'All files with the setuid bit set will allow anyone running these files to be temporarily assigned the UID of the file. While many system files depend on these attributes for proper operation, security problems can result if setuid is assigned to programs allowing reading and writing of files, or shell escapes. Only default vendor-supplied executables should have the setuid bit set.'
  desc 'check', 'If STIGID GEN000220 is satisfied, this is not a finding.

List all setuid files on the system.
Procedure:
# find / -perm -4000 -exec ls -l {} \\; | more

Note: Executing these commands may result in large listings of files; the output may be redirected to a file for easier analysis.

Ask the SA or IAO if files with the suid bit set have been documented. If any undocumented file has its suid bit set, this is a finding.'
  desc 'fix', 'Document the files with the suid bit set or unset the suid bit on the executable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42530r2_chk'
  tag severity: 'medium'
  tag gid: 'V-801'
  tag rid: 'SV-45184r2_rule'
  tag stig_id: 'GEN002380'
  tag gtitle: 'GEN002380'
  tag fix_id: 'F-38578r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000368']
  tag nist: ['CM-6 c']
end
