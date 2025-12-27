control 'SV-46010' do
  title 'The SSH daemon must be configured to not use Cipher-Block Chaining (CBC) ciphers.'
  desc 'The Cipher-Block Chaining (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plain text attacks and must not be used.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher ending with "cbc", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line.

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43291r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22459'
  tag rid: 'SV-46010r2_rule'
  tag stig_id: 'GEN005506'
  tag gtitle: 'GEN005506'
  tag fix_id: 'F-39374r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
