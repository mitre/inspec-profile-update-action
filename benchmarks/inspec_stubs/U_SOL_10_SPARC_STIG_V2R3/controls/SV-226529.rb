control 'SV-226529' do
  title 'The /etc/group file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.  Additionally, if password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Check the /etc/group file for password hashes.
Procedure:
# cut -d : -f 2 /etc/group | egrep -v '^(x|!)$'
If any password hashes are returned, this is a finding.
If no password hashes are returned, there is no finding."
  desc 'fix', 'Edit /etc/group and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28690r482975_chk'
  tag severity: 'medium'
  tag gid: 'V-226529'
  tag rid: 'SV-226529r603265_rule'
  tag stig_id: 'GEN001475'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28678r482976_fix'
  tag 'documentable'
  tag legacy: ['SV-26447', 'V-22348']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
