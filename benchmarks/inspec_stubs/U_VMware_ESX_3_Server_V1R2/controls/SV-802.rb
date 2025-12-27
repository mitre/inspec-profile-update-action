control 'SV-802' do
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
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8026r2_chk'
  tag severity: 'medium'
  tag gid: 'V-802'
  tag rid: 'SV-802r2_rule'
  tag stig_id: 'GEN002440'
  tag gtitle: 'GEN002440'
  tag fix_id: 'F-956r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000368']
  tag nist: ['CM-6 c']
end
