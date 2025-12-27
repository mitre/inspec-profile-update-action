control 'SV-227655' do
  title 'The /etc/group file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.  Additionally, if password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Check the /etc/group file for password hashes.
Procedure:
# cut -d : -f 2 /etc/group | egrep -v '^(x|!)$'
If any password hashes are returned, this is a finding.
If no password hashes are returned, there is no finding."
  desc 'fix', 'Edit /etc/group and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29817r488525_chk'
  tag severity: 'medium'
  tag gid: 'V-227655'
  tag rid: 'SV-227655r603266_rule'
  tag stig_id: 'GEN001475'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29805r488526_fix'
  tag 'documentable'
  tag legacy: ['V-22348', 'SV-26447']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
