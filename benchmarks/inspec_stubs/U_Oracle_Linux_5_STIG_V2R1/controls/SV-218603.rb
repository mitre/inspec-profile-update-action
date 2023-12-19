control 'SV-218603' do
  title 'The SSH client must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', %q(Check the SSH client configuration for allowed ciphers.

# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#'
 
If no lines are returned, or the returned ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and remove any ciphers not starting with "3des" or "aes" and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20078r556007_chk'
  tag severity: 'medium'
  tag gid: 'V-218603'
  tag rid: 'SV-218603r603259_rule'
  tag stig_id: 'GEN005510'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-20076r556008_fix'
  tag 'documentable'
  tag legacy: ['V-22461', 'SV-63593']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
