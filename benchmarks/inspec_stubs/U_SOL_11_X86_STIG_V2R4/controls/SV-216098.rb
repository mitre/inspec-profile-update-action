control 'SV-216098' do
  title 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors.'
  desc 'Cryptographic hashes provide quick password authentication while not actually storing the password.'
  desc 'check', 'Determine which cryptographic algorithms are configured.

# grep ^CRYPT /etc/security/policy.conf

If the command output does not include the lines:

CRYPT_DEFAULT=6
CRYPT_ALGORITHMS_ALLOW=5,6

this is a finding.'
  desc 'fix', 'The root role is required.

Configure the system to disallow the use of UNIX encryption and enable SHA256 as the default encryption hash.

# pfedit /etc/security/policy.conf

Check that the lines:
CRYPT_DEFAULT=6
CRYPT_ALGORITHMS_ALLOW=5,6

exist and are not commented out.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17336r372676_chk'
  tag severity: 'medium'
  tag gid: 'V-216098'
  tag rid: 'SV-216098r603268_rule'
  tag stig_id: 'SOL-11.1-040130'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-17334r372677_fix'
  tag 'documentable'
  tag legacy: ['V-48243', 'SV-61115']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
