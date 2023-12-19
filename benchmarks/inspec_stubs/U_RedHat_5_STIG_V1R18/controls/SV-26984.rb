control 'SV-26984' do
  title "The system's boot loader configuration file(s) must not have extended ACLs."
  desc "File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  If extended ACLs are present on the system's boot loader configuration file(s), these files may be vulnerable to unauthorized access or modification, which could compromise the system's boot process."
  desc 'check', "Check the permissions of the file.

# ls -lL /boot/grub/grub.conf

If the permissions of the file or directory contains a '+', an extended ACL is present. This is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37229r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22585'
  tag rid: 'SV-26984r1_rule'
  tag stig_id: 'GEN008740'
  tag gtitle: 'GEN008740'
  tag fix_id: 'F-24248r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
