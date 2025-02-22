control 'SRG-OS-000480-CLD-000110_rule' do
  title 'The Mission Owners must select and configure a CSO listed in the DISA PA DOD Cloud Catalog at Level 6 when hosting Classified DOD information.'
  desc 'Impact Level 6 is reserved for the storage and processing of classified information. Impact Level 6 information up to the SECRET level must be stored and processed in a dedicated cloud infrastructure located in facilities approved for the processing of classified information, rated at or above the highest level of classification of the information being stored and/or processed.'
  desc 'check', 'If the implementation is categorized as Impact Level 2-5, this not applicable.

Review the approval documentation and the DISA PA Cloud Catalog. Verify that the Cloud Service Offering is listed in the DISA PA DOD Cloud Catalog. Verify the Cloud Service Offering is listed in the DISA PA DOD Cloud Catalog at Level 6 when hosting Classified DOD information.

If Classified DOD information is being hosted in the IaaS/PaaS and the cloud service offering is not listed in the DISA PA DOD Cloud Catalog, Impact Level 6, this is a finding.'
  desc 'fix', 'This applies Impact Level 6.
FedRAMP Moderate, High.

Configure a cloud service offering listed in the DISA PA DOD Cloud Catalog for use with Impact Level 6 when hosting Classified DOD information. Specify in the SLA with the CSP and third-party providers compliance with applicable STIG configurations.'
  impact 0.7
  tag check_id: 'C-SRG-OS-000480-CLD-000110_chk'
  tag severity: 'high'
  tag gid: 'SRG-OS-000480-CLD-000110'
  tag rid: 'SRG-OS-000480-CLD-000110_rule'
  tag stig_id: 'SRG-OS-000480-CLD-000110'
  tag gtitle: 'SRG-OS-000480-CLD-000110'
  tag fix_id: 'F-SRG-OS-000480-CLD-000110_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
