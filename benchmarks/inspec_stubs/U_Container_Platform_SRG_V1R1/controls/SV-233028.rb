control 'SV-233028' do
  title 'Least privilege access and need to know must be required to access the container platform keystore.'
  desc 'The container platform keystore is used to store access keys and tokens for trusted access to and from the container platform. The keystore gives the container platform a method to store the confidential data in a secure way and to encrypt the data when at rest. If this data is not protected through access controls, it can be used to access trusted sources as the container platform breaking the trusted relationship. To circumvent unauthorized access to the keystore, the container platform must have access controls in place to only allow those individuals with keystore duties.'
  desc 'check', 'Review the container platform to determine if only those individuals with keystore duties have access to the container platform keystore. 

If users have access to the container platform keystore that do not have keystore duties, this is a finding.'
  desc 'fix', 'Configure the container platform to use least privilege and need to know when granting access to the container keystore. The fix ensures the proper roles and permissions are configured.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35964r598720_chk'
  tag severity: 'medium'
  tag gid: 'V-233028'
  tag rid: 'SV-233028r599509_rule'
  tag stig_id: 'SRG-APP-000033-CTR-000100'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-35932r598721_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
