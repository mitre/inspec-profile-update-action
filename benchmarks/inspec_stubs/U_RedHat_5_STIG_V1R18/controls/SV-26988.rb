control 'SV-26988' do
  title "The system's boot loader configuration file(s) must be group-owned by root, bin, sys, or system."
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modifications resulting from improper group ownership may compromise the boot loader configuration."
  desc 'check', 'Check the group ownership of the file.
# ls -lLd /boot/grub/grub.conf
If the group-owner of the file is not root, bin, sys, or system this is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37240r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22587'
  tag rid: 'SV-26988r1_rule'
  tag stig_id: 'GEN008780'
  tag gtitle: 'GEN008780'
  tag fix_id: 'F-32443r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
