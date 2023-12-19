control 'SV-44862' do
  title 'The system must enforce compliance of the entire password during authentification.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', "Verify no password hash in /etc/passwd or /etc/shadow begins with a character other than an underscore (_) or dollar sign ($).

# cut -d ':' -f2 /etc/passwd
# cut -d ':' -f2 /etc/shadow

If any password hash is present that does not have an initial underscore (_) or dollar sign ($) character, this is a finding."
  desc 'fix', 'Change the passwords for all accounts using non-compliant password hashes. 

(This requires GEN000590 is already met.)'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42324r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22302'
  tag rid: 'SV-44862r1_rule'
  tag stig_id: 'GEN000585'
  tag gtitle: 'GEN000585'
  tag fix_id: 'F-38295r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
