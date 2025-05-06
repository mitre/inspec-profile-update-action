control 'SV-26118' do
  title 'The SNMP service must require the use of a FIPS 140-2 approved encryption algorithm for protecting the privacy of SNMP messages.'
  desc 'The SNMP service must use AES or a FIPS 140-2 approved successor algorithm for protecting the privacy of communications.'
  desc 'check', 'Determine if the SNMP service uses a FIPS 140-2 approved encryption algorithm for protecting the privacy of SNMP messages. If it does not, this is a finding.'
  desc 'fix', 'Configure the SNMP service to use a FIPS 140-2 approved encryption algorithm for protecting the privacy of SNMP messages.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22449'
  tag rid: 'SV-26118r1_rule'
  tag stig_id: 'GEN005307'
  tag gtitle: 'GEN005307'
  tag fix_id: 'F-26294r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
