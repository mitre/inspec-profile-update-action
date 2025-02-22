control 'SV-221680' do
  title 'The Oracle Linux operating system must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.'
  desc 'check', 'Verify the user and group account administration utilities are configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is "SHA512".

Check that the system is configured to create "SHA512" hashed passwords with the following command:

# grep -i sha512 /etc/libuser.conf 

crypt_style = sha512

If the "crypt_style" variable is not set to "sha512", is not in the defaults section, is commented out, or does not exist, this is a finding.'
  desc 'fix', 'Configure the operating system to store only SHA512 encrypted representations of passwords.

Add or update the following line in "/etc/libuser.conf" in the [defaults] section: 

crypt_style = sha512'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23395r419112_chk'
  tag severity: 'medium'
  tag gid: 'V-221680'
  tag rid: 'SV-221680r603260_rule'
  tag stig_id: 'OL07-00-010220'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-23384r419113_fix'
  tag 'documentable'
  tag legacy: ['SV-108203', 'V-99099']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
