control 'SV-218600' do
  title 'The operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.

By specifying a cipher list with the order of ciphers being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers.

# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#'

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or is commented out, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any ciphers not starting with "aes" and remove any ciphers ending with "cbc".

If necessary, add a "Ciphers" line.

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon.

# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20075r603335_chk'
  tag severity: 'medium'
  tag gid: 'V-218600'
  tag rid: 'SV-218600r603337_rule'
  tag stig_id: 'GEN005505'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-20073r603336_fix'
  tag 'documentable'
  tag legacy: ['V-22458', 'SV-63561']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
