control 'SV-221678' do
  title 'The Oracle Linux operating system must be configured to use the shadow file to store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.'
  desc 'check', %q(Verify the system's shadow file is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the following command:

# grep -i encrypt /etc/login.defs
ENCRYPT_METHOD SHA512

If the "/etc/login.defs" configuration file does not exist or allows for password hashes other than SHA512 to be used, this is a finding.)
  desc 'fix', 'Configure the operating system to store only SHA512 encrypted representations of passwords.

Add or update the following line in "/etc/login.defs":

ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23393r419106_chk'
  tag severity: 'medium'
  tag gid: 'V-221678'
  tag rid: 'SV-221678r877397_rule'
  tag stig_id: 'OL07-00-010210'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-23382r419107_fix'
  tag 'documentable'
  tag legacy: ['V-99097', 'SV-108201']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
