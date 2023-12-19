control 'SV-26260' do
  title "The system's boot loader configuration file(s) must not have extended ACLs."
  desc "File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  If extended ACLs are present on the system's boot loader configuration file(s), these files may be vulnerable to unauthorized access or modification, which could compromise the system's boot process."
  desc 'check', 'If the system does not use GRUB, this is not applicable.

Check the grub.conf file for an extended ACL.
# ls -lL grub.conf 
If the listed permissions contain a "+", this file has an extended ACL, and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the grub.conf file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29320r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22585'
  tag rid: 'SV-26260r1_rule'
  tag stig_id: 'GEN008740'
  tag gtitle: 'GEN008740'
  tag fix_id: 'F-26352r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
