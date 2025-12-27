control 'SV-227584' do
  title 'The system must enforce compliance of the entire password during authentication.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', "Verify no password hash in /etc/passwd or /etc/shadow begins with a character other than an underscore (_) or dollar sign ($).

# cut -d ':' -f2 /etc/passwd | egrep -v '^[*!$_]'
# cut -d ':' -f2 /etc/shadow | egrep -v '^[*!$_]'

If any unlocked password hash is present without an initial underscore (_) or dollar sign ($) character, this is a finding."
  desc 'fix', 'Edit /etc/security/policy.conf and add or change the CRYPT_DEFAULT setting to something other than __unix__, such as 6.  Allowable values for CRYPT_DEFAULT may be found in the /etc/security/crypt.conf file.

Change any passwords using non-compliant hashes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36444r602935_chk'
  tag severity: 'medium'
  tag gid: 'V-227584'
  tag rid: 'SV-227584r603266_rule'
  tag stig_id: 'GEN000585'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-36408r602936_fix'
  tag 'documentable'
  tag legacy: ['V-22302', 'SV-26318']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
