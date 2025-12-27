control 'SV-221915' do
  title 'The Central Log Server must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to protect audit information from any unauthorized modification.

If the Central Log Server is not configured to protect audit information from any unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23630r420087_chk'
  tag severity: 'medium'
  tag gid: 'V-221915'
  tag rid: 'SV-221915r420089_rule'
  tag stig_id: 'SRG-APP-000119-AU-000110'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-23619r420088_fix'
  tag 'documentable'
  tag legacy: ['SV-109163', 'V-100059']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
