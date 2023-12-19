control 'SV-227548' do
  title 'The root account must be the only account with GID of 0.'
  desc 'Accounts with a GID of 0 have root group privileges.'
  desc 'check', "Check passwd and group files for non-root user ids and group ids with a GID of 0.

# more /etc/passwd 
# more /etc/group

OR

# awk -F: '$4 == 0' /etc/passwd
# awk -F: '$3 == 0' /etc/group

Confirm the only account with a group id of 0 is root.

If the root account is not the only account with GID of 0, this is a finding."
  desc 'fix', 'Change the default GID of non-root accounts to a valid GID other than 0.'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29710r488177_chk'
  tag severity: 'high'
  tag gid: 'V-227548'
  tag rid: 'SV-227548r603266_rule'
  tag stig_id: 'GEN000000-SOL00440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29698r488178_fix'
  tag 'documentable'
  tag legacy: ['SV-12534', 'V-12033']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
