control 'SV-227893' do
  title 'The operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.

By specifying a cipher list with the order of ciphers being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.

'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers.

# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#'

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or is commented out, this is a finding.)
  desc 'fix', 'Edit /etc/ssh/sshd_config and change or set the Ciphers line to the following.

Ciphers aes256-ctr, aes192-ctr, aes128-ctr'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30055r622317_chk'
  tag severity: 'medium'
  tag gid: 'V-227893'
  tag rid: 'SV-227893r603855_rule'
  tag stig_id: 'GEN005505'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-30043r622318_fix'
  tag satisfies: ['SRG-OS-000033', 'SRG-OS-000505', 'SRG-OS-000555']
  tag 'documentable'
  tag legacy: ['V-22458', 'SV-41035']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
