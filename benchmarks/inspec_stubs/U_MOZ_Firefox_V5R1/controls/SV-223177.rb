control 'SV-223177' do
  title 'Deprecated ciphers must be disabled.'
  desc 'A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “security.ssl3.rsa_des_ede3_sha" is set to “false” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “security.ssl3.rsa_des_ede3_sha" is set and locked to the value of “false”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24850r531348_chk'
  tag severity: 'medium'
  tag gid: 'V-223177'
  tag rid: 'SV-223177r612236_rule'
  tag stig_id: 'DTBF235'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-24838r531349_fix'
  tag 'documentable'
  tag legacy: ['SV-111851', 'V-102889']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
