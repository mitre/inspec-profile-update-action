control 'SV-35188' do
  title 'The SSH client must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'fix', 'Edit the configuration file and remove any ciphers that do not meet the following: 3des-ctr or aes-NNN-ctr (NNN=128, 192 or 256). If necessary, add the Ciphers entry with one or more of the above keyword values.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22461'
  tag rid: 'SV-35188r1_rule'
  tag stig_id: 'GEN005510'
  tag gtitle: 'GEN005510'
  tag fix_id: 'F-32007r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
