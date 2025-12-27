control 'SV-248535' do
  title 'The OL 8 shadow password suite must be configured to use a sufficient number of hashing rounds.'
  desc 'The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy. 
 
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Check that a minimum number of hash rounds is configured by running the following command:

$ sudo egrep "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "5000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the value for either is below "5000", this is a finding.'
  desc 'fix', 'Configure OL 8 to encrypt all stored passwords with a strong cryptographic hash. 
 
Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "5000": 
 
SHA_CRYPT_MIN_ROUNDS 5000'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51969r818599_chk'
  tag severity: 'medium'
  tag gid: 'V-248535'
  tag rid: 'SV-248535r818601_rule'
  tag stig_id: 'OL08-00-010130'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-51923r818600_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
