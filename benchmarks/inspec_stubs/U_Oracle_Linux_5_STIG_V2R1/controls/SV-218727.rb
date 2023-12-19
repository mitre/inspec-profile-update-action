control 'SV-218727' do
  title 'The systems boot loader configuration file(s) must not have extended ACLs.'
  desc "File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  If extended ACLs are present on the system's boot loader configuration file(s), these files may be vulnerable to unauthorized access or modification, which could compromise the system's boot process."
  desc 'check', "Check the permissions of the file.

# ls -lL /boot/grub/grub.conf

If the permissions of the file or directory contains a '+', an extended ACL is present. This is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20202r562951_chk'
  tag severity: 'medium'
  tag gid: 'V-218727'
  tag rid: 'SV-218727r603259_rule'
  tag stig_id: 'GEN008740'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20200r562952_fix'
  tag 'documentable'
  tag legacy: ['V-22585', 'SV-63091']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
