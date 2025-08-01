control 'SV-26754' do
  title 'The SSH client must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', "Check the SSH client configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, the returned ciphers list contains any cipher not starting with 3des or aes, this is a finding."
  desc 'fix', 'Edit /etc/ssh/ssh_config and add or edit the "Ciphers" line.  Only include ciphers that start with "3des" or "aes" and do not contain "cbc".  For the list of available ciphers for the particular version of your software, consult the ssh_config manpage.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22461'
  tag rid: 'SV-26754r1_rule'
  tag stig_id: 'GEN005510'
  tag gtitle: 'GEN005510'
  tag fix_id: 'F-24004r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
