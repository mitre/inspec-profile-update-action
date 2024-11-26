control 'SV-226549' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by root, bin, or sys.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Verify the skeleton files are group-owned by root, bin, or sys.

Procedure:
# ls -alL /etc/skel

If a skeleton file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the skeleton file to root.

Procedure:
# chgrp <group> /etc/skel/[skeleton file]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28710r483053_chk'
  tag severity: 'medium'
  tag gid: 'V-226549'
  tag rid: 'SV-226549r603265_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28698r483054_fix'
  tag 'documentable'
  tag legacy: ['V-22358', 'SV-39901']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
