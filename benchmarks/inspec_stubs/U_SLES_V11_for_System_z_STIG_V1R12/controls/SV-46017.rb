control 'SV-46017' do
  title 'The SSH client must be configured to not use Cipher-Block Chaining (CBC)-based ciphers.'
  desc 'The (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen-plaintext attacks and must not be used.'
  desc 'check', %q(Check the SSH client configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher ending with "cbc", this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43294r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22462'
  tag rid: 'SV-46017r1_rule'
  tag stig_id: 'GEN005511'
  tag gtitle: 'GEN005511'
  tag fix_id: 'F-39381r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
