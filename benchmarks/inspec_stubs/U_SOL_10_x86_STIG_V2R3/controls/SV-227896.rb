control 'SV-227896' do
  title 'The SSH client must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.

'
  desc 'check', "Check the SSH client configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, the returned ciphers list contains any cipher not starting with 3des or aes, this is a finding."
  desc 'fix', 'Edit /etc/ssh/ssh_config and add or edit the "Ciphers" line.  Only include ciphers that start with "3des" or "aes" and do not contain "cbc".  For the list of available ciphers for the particular version of your software, consult the ssh_config manpage.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30058r490093_chk'
  tag severity: 'medium'
  tag gid: 'V-227896'
  tag rid: 'SV-227896r603266_rule'
  tag stig_id: 'GEN005510'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-30046r490094_fix'
  tag satisfies: ['SRG-OS-000033', 'SRG-OS-000505', 'SRG-OS-000555']
  tag 'documentable'
  tag legacy: ['V-22461', 'SV-26754']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
