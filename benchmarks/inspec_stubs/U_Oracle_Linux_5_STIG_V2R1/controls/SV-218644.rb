control 'SV-218644' do
  title 'The smbpasswd file must be group-owned by root.'
  desc 'If the smbpasswd file is not group-owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check "smbpasswd" ownership:

# ls -lL /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If the "smbpasswd" file is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure that the group owner of the smbpasswd file is root.
 
For instance:
# chgrp root /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20119r556130_chk'
  tag severity: 'medium'
  tag gid: 'V-218644'
  tag rid: 'SV-218644r603259_rule'
  tag stig_id: 'GEN006180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20117r556131_fix'
  tag 'documentable'
  tag legacy: ['V-1058', 'SV-64069']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
