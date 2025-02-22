control 'SV-237338' do
  title 'The ArcGIS Server SSL settings must use NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'Review the ArcGIS Server configuration to ensure the application implements NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. Substitute the target environment’s values for [bracketed] variables.

Within IIS >> within the [“arcgis”] application >> SSL Settings >> Verify that “Require SSL” is checked.
If “Require SSL” is not checked, this is a finding.

Note: To comply with this control, the Active Directory domain on which the ArcGIS Server and the IIS system are deployed must implement policies which enforce FIPS 140-2 compliance.

This control is not applicable for ArcGIS Servers which are deployed as part of a solution which ensures user web service traffic flows through third-party DoD compliant transport encryption devices (such as a load balancer that supports TLS encryption using DoD-approved certificates.)

This control is not applicable for ArcGIS Servers which are not deployed with the ArcGIS Web Adapter component.'
  desc 'fix', 'Configure the ArcGIS Server to implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. Substitute the target environment’s values for [bracketed] variables.

Within IIS >> within the "[arcgis]" application >> SSL Settings >> check "Require SSL".'
  impact 0.7
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40557r642831_chk'
  tag severity: 'high'
  tag gid: 'V-237338'
  tag rid: 'SV-237338r879944_rule'
  tag stig_id: 'AGIS-00-000187'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-40520r642832_fix'
  tag satisfies: ['SRG-APP-000416', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442', 'SRG-APP-000514']
  tag 'documentable'
  tag legacy: ['SV-80007', 'V-65517']
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002450']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'SC-13 b']
end
