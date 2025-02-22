control 'SV-218605' do
  title 'The SSH client must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', "Check the SSH client configuration for allowed MACs.

# grep -i macs /etc/ssh/ssh_config | grep -v '^#'
 
If no lines are returned, or the returned MACs list contains any MAC that is not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list, this is a finding."
  desc 'fix', 'Edit the SSH client configuration and remove any MACs that are not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list. 

If necessary, add a MACs line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20080r556013_chk'
  tag severity: 'medium'
  tag gid: 'V-218605'
  tag rid: 'SV-218605r603259_rule'
  tag stig_id: 'GEN005512'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-20078r556014_fix'
  tag 'documentable'
  tag legacy: ['V-22463', 'SV-63669']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
