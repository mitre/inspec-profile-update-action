control 'SV-253064' do
  title 'TOSS must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Verify that the TOSS shadow password suite configuration is set to encrypt password with a FIPS 140-2-approved cryptographic hashing algorithm.

Check the hashing algorithm that is being used to hash passwords with the following command:

$ sudo grep -i crypt /etc/login.defs 
ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, this is a finding.'
  desc 'fix', 'Configure TOSS to encrypt all stored passwords. 

Edit/Modify the following line in the "/etc/login.defs" file and set "ENCRYPT_METHOD" to SHA512.

ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56517r824862_chk'
  tag severity: 'medium'
  tag gid: 'V-253064'
  tag rid: 'SV-253064r824864_rule'
  tag stig_id: 'TOSS-04-040090'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-56467r824863_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
