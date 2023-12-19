control 'SV-26751' do
  title 'The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', "Check the SSH daemon configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher not starting with 3des or aes, this is a finding."
  desc 'fix', 'Edit /etc/ssh/sshd_config and add or edit the "Ciphers" line.  Only include ciphers that start with "3des" or "aes" and do not contain "cbc".  For the list of available ciphers for the particular version of your software, consult the sshd_config manpage.

Restart the SSH daemon.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27760r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22458'
  tag rid: 'SV-26751r1_rule'
  tag stig_id: 'GEN005505'
  tag gtitle: 'GEN005505'
  tag fix_id: 'F-24001r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
