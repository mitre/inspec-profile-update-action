control 'SV-218604' do
  title 'The SSH client must be configured to not use Cipher-Block Chaining (CBC)-based ciphers.'
  desc 'The (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen-plaintext attacks and must not be used.'
  desc 'check', %q(Check the SSH client configuration for allowed ciphers.

# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#'
 
If no lines are returned, or the returned ciphers list contains any cipher ending with "cbc", this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and remove any ciphers not starting with "3des" or "aes" and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20079r556010_chk'
  tag severity: 'medium'
  tag gid: 'V-218604'
  tag rid: 'SV-218604r603259_rule'
  tag stig_id: 'GEN005511'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20077r556011_fix'
  tag 'documentable'
  tag legacy: ['V-22462', 'SV-63595']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
