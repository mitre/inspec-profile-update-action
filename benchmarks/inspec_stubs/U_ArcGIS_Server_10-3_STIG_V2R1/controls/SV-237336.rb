control 'SV-237336' do
  title 'The ArcGIS Server must accept and electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure that the application accepts Personal Identity Verification (PIV) credentials. Substitute the target environment’s values for [bracketed] variables.

Within IIS >> within the [“arcgis”] application >> Authentication >> Verify that “Windows Authentication” is “Enabled”.
Verify that “Anonymous Authentication” is “Disabled”.
If “Windows Authentication” is not enabled, or “Anonymous Authentication” is enabled, this is a finding.

Within IIS >> within the [“arcgis”] application >> SSL Settings >> Verify the setting “Client Certificates:” is set to “Accept” or “Require”
If “Client Certificates:” is set to “Ignore” this is a finding.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD compliant certificate authentication solutions.'
  desc 'fix', 'Configure ArcGIS for Server to accept Personal Identity Verification (PIV) credentials. Substitute the target environment’s values for [bracketed] variables.

Enable Active Directory Client Certificate Authentication "To map client certificates by using Active Directory mapping."'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40555r642825_chk'
  tag severity: 'medium'
  tag gid: 'V-237336'
  tag rid: 'SV-237336r879764_rule'
  tag stig_id: 'AGIS-00-000171'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-40518r642826_fix'
  tag satisfies: ['SRG-APP-000391', 'SRG-APP-000392']
  tag 'documentable'
  tag legacy: ['SV-79999', 'V-65509']
  tag cci: ['CCI-001953', 'CCI-001954']
  tag nist: ['IA-2 (12)', 'IA-2 (12)']
end
