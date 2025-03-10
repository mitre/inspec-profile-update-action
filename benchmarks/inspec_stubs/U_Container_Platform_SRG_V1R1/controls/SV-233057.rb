control 'SV-233057' do
  title 'The container platform must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Review the container platform configuration to determine where audit information is stored. 

If the audit log data is not protected from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the container platform to protect the storage of audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35993r598807_chk'
  tag severity: 'medium'
  tag gid: 'V-233057'
  tag rid: 'SV-233057r599509_rule'
  tag stig_id: 'SRG-APP-000119-CTR-000245'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-35961r598808_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
