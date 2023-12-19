control 'SV-237138' do
  title 'ColdFusion must use cryptography mechanisms to protect the integrity of data sent to the PDF Service.'
  desc 'Protecting data being sent to the PDF Service for PDF document creation protects the data from being read or modified before the document is created and returned to the requesting application.  This protection can be implemented by using https over the plaintext transport protocol of http.'
  desc 'check', 'Access the "PDF Service" page under the "Data & Services" menu within the Administrator Console.

If there are no PDF Service Managers defined, the finding is not applicable. 

If any PDF Service Managers listed have "Https Enabled" set to "NO", this is a finding.'
  desc 'fix', 'If there are no PDF Service Managers in use, the finding is not applicable. 

Access the "PDF Service" page under the "Data & Services" menu within the Administrator Console.  Edit each service and check the "Https Enabled" option.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40357r641507_chk'
  tag severity: 'medium'
  tag gid: 'V-237138'
  tag rid: 'SV-237138r641509_rule'
  tag stig_id: 'CF11-01-000004'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-40320r641508_fix'
  tag 'documentable'
  tag legacy: ['SV-76839', 'V-62349']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
