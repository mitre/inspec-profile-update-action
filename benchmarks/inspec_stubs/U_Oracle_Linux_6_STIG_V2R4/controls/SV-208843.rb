control 'SV-208843' do
  title 'The system boot loader must require authentication.'
  desc 'Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.'
  desc 'check', 'To verify the boot loader password has been set and encrypted, run the following command: 

# grep password /boot/grub/grub.conf

The output should show the following: 

password --encrypted $6$[rest-of-the-password-hash]

If it does not, this is a finding.'
  desc 'fix', 'The grub boot loader should have password protection enabled to protect boot-time settings. To do so, select a password and then generate a hash from it by running the following command: 

# grub-crypt --sha-512

When prompted to enter a password, insert the following line into "/boot/grub/grub.conf" immediately after the header comments. (Use the output from "grub-crypt" as the value of [password-hash]): 

password --encrypted [password-hash]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9096r357509_chk'
  tag severity: 'medium'
  tag gid: 'V-208843'
  tag rid: 'SV-208843r603263_rule'
  tag stig_id: 'OL6-00-000068'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-9096r357510_fix'
  tag 'documentable'
  tag legacy: ['V-50945', 'SV-65151']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
