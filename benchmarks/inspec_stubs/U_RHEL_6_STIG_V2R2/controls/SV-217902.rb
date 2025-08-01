control 'SV-217902' do
  title 'The system boot loader configuration file(s) must be group-owned by root.'
  desc 'The "root" group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.'
  desc 'check', 'To check the group ownership of "/boot/grub/grub.conf", run the command: 

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate the group-owner is "root".
If it does not, this is a finding.'
  desc 'fix', 'The file "/boot/grub/grub.conf" should be group-owned by the "root" group to prevent destruction or modification of the file. To properly set the group owner of "/boot/grub/grub.conf", run the command: 

# chgrp root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19383r376721_chk'
  tag severity: 'medium'
  tag gid: 'V-217902'
  tag rid: 'SV-217902r603264_rule'
  tag stig_id: 'RHEL-06-000066'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19381r376722_fix'
  tag 'documentable'
  tag legacy: ['V-38581', 'SV-50382']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
