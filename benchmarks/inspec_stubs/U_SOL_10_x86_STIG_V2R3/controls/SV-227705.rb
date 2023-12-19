control 'SV-227705' do
  title 'The owner, group owner, mode, ACL, and location of files with the setuid bit set must be documented using site-defined procedures.'
  desc 'All files with the setuid bit set will allow anyone running these files to be temporarily assigned the UID of the file. While many system files depend on these attributes for proper operation, security problems can result if setuid is assigned to programs that allow reading and writing of files, or shell escapes.  Only default vendor-supplied executables should have the setuid bit set.'
  desc 'check', 'Files with the setuid bit set will allow anyone running these files to be temporarily assigned the user or group ID of the file.  If an executable with setuid allows shell escapes, the user can operate on the system with the effective permission rights of the user or group owner.

List all setuid files on the system.
Procedure:
# find /  -perm -4000 -exec ls -l {} \\; | more 

NOTE:  Executing these commands may result in large listings of files; the output may be redirected to a file for easier analysis.

Ask the SA or IAO if files with the setuid bit set have been documented.  If any undocumented file has its setuid bit set, this is a finding.'
  desc 'fix', 'Document the files with the setuid bit set or unset the setuid bit on the executable.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29867r488696_chk'
  tag severity: 'medium'
  tag gid: 'V-227705'
  tag rid: 'SV-227705r603266_rule'
  tag stig_id: 'GEN002380'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29855r488697_fix'
  tag 'documentable'
  tag legacy: ['V-801', 'SV-801']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
