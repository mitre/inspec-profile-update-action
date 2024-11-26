control 'SV-217126' do
  title 'The SUSE operating system must employ FIPS 140-2-approved cryptographic hashing algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'Verify the SUSE operating system configures the shadow password suite configuration to encrypt passwords using a strong cryptographic hash.

Check that a minimum number of hash rounds is configured by running the following command:

egrep "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "5000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the highest value for either is below "5000", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "5000":

SHA_CRYPT_MIN_ROUNDS 5000'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18354r369534_chk'
  tag severity: 'medium'
  tag gid: 'V-217126'
  tag rid: 'SV-217126r877397_rule'
  tag stig_id: 'SLES-12-010240'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-18352r369535_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag legacy: ['V-77107', 'SV-91803']
  tag cci: ['CCI-000803', 'CCI-000196']
  tag nist: ['IA-7', 'IA-5 (1) (c)']
end
