control 'SV-46004' do
  title 'The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any ciphers not starting with "3des" or "aes". If necessary, add a "Ciphers" line.

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43286r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22458'
  tag rid: 'SV-46004r2_rule'
  tag stig_id: 'GEN005505'
  tag gtitle: 'GEN005505'
  tag fix_id: 'F-39369r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
