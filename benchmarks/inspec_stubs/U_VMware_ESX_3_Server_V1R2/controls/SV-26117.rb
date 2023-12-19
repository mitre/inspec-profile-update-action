control 'SV-26117' do
  title 'The SNMP service must require the use of a FIPS 140-2 approved cryptographic hash algorithm as part of its authentication and integrity methods.'
  desc 'The SNMP service must use SHA-1 or a FIPS 140-2 approved successor for authentication and integrity.'
  desc 'check', 'Determine if the SNMP service uses a FIPS 140-2 approved cryptographic hash algorithm as part of its authentication and integrity methods. If it does not, this is a finding.'
  desc 'fix', 'Configure the SNMP service to use a FIPS 140-2 approved cryptographic hash algorithm as part of its authentication and integrity methods.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29268r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22448'
  tag rid: 'SV-26117r1_rule'
  tag stig_id: 'GEN005306'
  tag gtitle: 'GEN005306'
  tag fix_id: 'F-26293r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
