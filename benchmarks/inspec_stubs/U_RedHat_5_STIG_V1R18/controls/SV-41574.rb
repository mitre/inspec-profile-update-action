control 'SV-41574' do
  title 'The smbpasswd file must be group-owned by root.'
  desc 'If the smbpasswd file is not group-owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check "smbpasswd" ownership:

# ls -lL /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If the "smbpasswd" file is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure that the group owner of the smbpasswd file is root.
 
For instance:

# chgrp root /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-40075r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1058'
  tag rid: 'SV-41574r1_rule'
  tag stig_id: 'GEN006180'
  tag gtitle: 'GEN006180'
  tag fix_id: 'F-35231r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
