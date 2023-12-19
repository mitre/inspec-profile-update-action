control 'SV-35220' do
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', %q(Check the SSH daemon configuration for allowed MACs. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | egrep -i "macs"

If no lines are returned, or the returned MACs list contains any MAC that is not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs that are not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list. If necessary, add a MACs line.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36635r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22460'
  tag rid: 'SV-35220r2_rule'
  tag stig_id: 'GEN005507'
  tag gtitle: 'GEN005507'
  tag fix_id: 'F-32005r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
