control 'SV-26262' do
  title "The system's boot loader configuration file(s) must be group-owned by root, bin, sys, or system."
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modifications resulting from improper group ownership may compromise the boot loader configuration."
  desc 'check', 'For GRUB:

Check the group owner of the grub.conf file.

Procedure:
# ls -lL grub.conf

If the group owner is not root or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the grub.conf file to root or sys.

Procedure:
# chgrp root grub.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29322r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22587'
  tag rid: 'SV-26262r1_rule'
  tag stig_id: 'GEN008780'
  tag gtitle: 'GEN008780'
  tag fix_id: 'F-26354r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
