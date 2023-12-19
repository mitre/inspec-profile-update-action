control 'SV-217123' do
  title 'The SUSE operating system must employ FIPS 140-2-approved cryptographic hashing algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'Verify the SUSE operating system requires the shadow password suite configuration be set to encrypt interactive user passwords using a strong cryptographic hash.

Check that the interactive user account passwords are using a strong password hash with the following command:

> sudo cut -d: -f2 /etc/shadow

$6$kcOnRq/5$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/

Password hashes "!" or "*" indicate inactive accounts not available for logon and are not evaluated. 

If any interactive user password hash does not begin with "$6", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "ENCRYPT_METHOD" to have a value of "SHA512".

ENCRYPT_METHOD SHA512

Lock all interactive user accounts not using SHA512 hashing until the passwords can be regenerated.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18351r646690_chk'
  tag severity: 'medium'
  tag gid: 'V-217123'
  tag rid: 'SV-217123r646692_rule'
  tag stig_id: 'SLES-12-010220'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-18349r646691_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag legacy: ['V-77099', 'SV-91795']
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
end
