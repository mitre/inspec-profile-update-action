control 'SV-227707' do
  title 'The owner, group-owner, mode, ACL, and location of files with the setgid bit set must be documented using site-defined procedures.'
  desc 'All files with the setgid bit set will allow anyone running these files to be temporarily assigned the GID of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs that allow reading and writing of files, or shell escapes.'
  desc 'check', 'Locate all setgid files on the system.

Procedure:
# find /  -perm -2000

If the ownership, permissions, location, and ACLs of all files with the setgid bit set are not documented, this is a finding.'
  desc 'fix', 'All files with the setgid bit set will be documented in the system baseline and authorized by the Information Systems Security Officer. Locate all setgid files with the following command.

find / -perm -2000 -exec ls -lLd {} \\;

Ensure setgid files are part of the operating system software, documented application software, documented utility software, or documented locally developed software. Ensure none are text files or shell programs.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36459r602980_chk'
  tag severity: 'medium'
  tag gid: 'V-227707'
  tag rid: 'SV-227707r603266_rule'
  tag stig_id: 'GEN002440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36423r602981_fix'
  tag 'documentable'
  tag legacy: ['V-802', 'SV-802']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
