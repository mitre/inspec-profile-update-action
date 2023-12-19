control 'SV-46015' do
  title 'The SSH client must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', %q(Check the SSH client configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and remove any ciphers not starting with "3des" or "aes". If necessary, add a "Ciphers" line.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43293r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22461'
  tag rid: 'SV-46015r1_rule'
  tag stig_id: 'GEN005510'
  tag gtitle: 'GEN005510'
  tag fix_id: 'F-39378r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
