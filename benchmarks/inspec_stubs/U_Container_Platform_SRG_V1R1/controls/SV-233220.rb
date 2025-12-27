control 'SV-233220' do
  title 'The container platform keystore must implement encryption to prevent unauthorized disclosure of information at rest within the container platform.'
  desc 'Container platform keystore is used for container deployments for persistent storage of all its REST API objects. These objects are sensitive in nature and should be encrypted at rest to avoid any unauthorized disclosure. Selection of a cryptographic mechanism is based on the need to protect the confidentiality of organizational information. The strength of mechanism is commensurate with the security category and/or classification of the information.'
  desc 'check', 'Review container platform keystore documentation and configuration to verify encryption levels meet the information sensitivity level. 

If the container platform keystore encryption configuration does not meet system requirements, this is a finding.'
  desc 'fix', 'Configure the container platform keystore encryption to maintain the confidentiality and integrity of information for applicable sensitivity level.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36156r599296_chk'
  tag severity: 'medium'
  tag gid: 'V-233220'
  tag rid: 'SV-233220r599509_rule'
  tag stig_id: 'SRG-APP-000429-CTR-001060'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-36124r599297_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
