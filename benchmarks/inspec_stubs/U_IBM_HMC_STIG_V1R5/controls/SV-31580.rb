control 'SV-31580' do
  title 'Connection to the Internet for IBM remote support must be in compliance with the Remote Access STIGs.'
  desc 'Failure to securely connect to remote sites can leave systems open to multiple attacks and security violations through the network. Failure to securely implement remote support connections can lead to unauthorized access or denial of service attacks on the Hardware Management Console.'
  desc 'check', 'Have the Network Security Engineer or system Programmer check, that the remote Internet connection for IBM RSF support has met the requirements of the Remote Access STIGs. For controls that are a part of IBM’s closed system that cannot be updated or changed by customers, review provided documentation, such as found in the HMC Broadband Support manuals or a letter of Attestation provided by IBM assuring compliance. If the security measures in the Remote Access STIGs are not fully compliant and there is no supporting documentation or Letter of attestation on file with the IAM/IAO this is a finding.'
  desc 'fix', 'The Network Security Officer or System Programmer should make any changes required for IBM RSF to meet the requirements stipulated in the Remote Access STIGs. Also any documentation or letters of Attestation should be placed on file with the IAM/IAO.  The letter of attestation must be signed by an authorized representative of IBM. The letter should contain certification that the security measures identified in the Remote Access STIGs are in compliance.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-54017r2_chk'
  tag severity: 'high'
  tag gid: 'V-25400'
  tag rid: 'SV-31580r2_rule'
  tag stig_id: 'HMC0220'
  tag gtitle: 'HMC0220'
  tag fix_id: 'F-56715r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Network Security Officer']
  tag ia_controls: 'EBRP-1, EBRU-1'
  tag cci: ['CCI-002310']
  tag nist: ['AC-17 a']
end
