control 'SV-99177' do
  title 'The alias files must be group-owned by root, or a system group.'
  desc 'If the aliases and aliases.db file are not group-owned by root or a system group, an unauthorized user may modify one or both of the files to add aliases to run malicious code or redirect email.'
  desc 'check', 'Check the group ownership of the alias files:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If the files are not group-owned by "root", this is a finding.'
  desc 'fix', 'Change the group owner of the alias files to "root":

# chgrp root /etc/aliases
# chgrp root /etc/aliases.db'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88219r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88527'
  tag rid: 'SV-99177r1_rule'
  tag stig_id: 'VROM-SL-000545'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
