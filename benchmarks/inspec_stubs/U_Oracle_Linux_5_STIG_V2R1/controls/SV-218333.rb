control 'SV-218333' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by root, bin, sys, system, or other.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Verify the skeleton files are group-owned by root.

Procedure:
# ls -alL /etc/skel
If a skeleton file is not group-owned by root, bin, sys, system, or other this is a finding.'
  desc 'fix', 'Change the group-owner of the skeleton file to root, bin, sys, system, or other.

Procedure:
# chgrp <group> /etc/skel/[skeleton file]
or:
# ls -L /etc/skel|xargs stat -L -c %G:%n|egrep -v "^(root|bin|sy|sytem|other):"|cut -d: -f2|chgrp root
will change the group of all files not already one of the approved group to root.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19808r568864_chk'
  tag severity: 'medium'
  tag gid: 'V-218333'
  tag rid: 'SV-218333r603259_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19806r568865_fix'
  tag 'documentable'
  tag legacy: ['V-22358', 'SV-63323']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
