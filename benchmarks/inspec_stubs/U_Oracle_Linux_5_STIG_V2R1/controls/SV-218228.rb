control 'SV-218228' do
  title 'The system must enforce compliance of the entire password during authentication.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', %q(Verify no valid password hash in /etc/passwd or /etc/shadow begins with a character other than an underscore (_) or dollar sign ($).

# cut -d ':' -f2 /etc/passwd
# cut -d ':' -f2 /etc/shadow

If any valid password hash is present that does not have an initial underscore (_) or dollar sign ($) character, this is a finding.

Note: Locked accounts are indicated by a leading exclamation point (!). System accounts, other than "root", may have an asterisk (*) in the password field. On systems utilizing shadow passwords, the password field in /etc/passwd will be a single "x".)
  desc 'fix', 'Change the passwords for all accounts using non-compliant password hashes. 

(This requires GEN000590 is already met.)'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19703r554021_chk'
  tag severity: 'medium'
  tag gid: 'V-218228'
  tag rid: 'SV-218228r603259_rule'
  tag stig_id: 'GEN000585'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-19701r554022_fix'
  tag 'documentable'
  tag legacy: ['V-22302', 'SV-63933']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
