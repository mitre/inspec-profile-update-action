control 'SV-251692' do
  title 'Splunk Enterprise must accept the DoD CAC or other PKI credential for identity management and personal authentication.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as a primary component of layered protection for national security systems. DoD has approved other methods of PKI, including YubiKey, RSA tokens, etc.

If the application cannot meet this requirement, the risk may be mitigated through use of an authentication server.'
  desc 'check', 'If the instance being checked is in a distributed environment and has the web interface disabled, this check is N/A.

Verify that Splunk Enterprise is configured to use the DoD CAC or other PKI credential to log in to the application.

If it is not configured to allow the use of the DoD CAC or other PKI credential, this is a finding.'
  desc 'fix', 'Configure an SSO proxy service using Apache, IIS, F5, SAML, etc., to provide PKI credentials to Splunk Enterprise. 

Examples for Apache and F5 are provided using the supplemental documentation included in this package to be used in addition to the Splunk documentation.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55130r808310_chk'
  tag severity: 'high'
  tag gid: 'V-251692'
  tag rid: 'SV-251692r879764_rule'
  tag stig_id: 'SPLK-CL-000490'
  tag gtitle: 'SRG-APP-000391-AU-002290'
  tag fix_id: 'F-55084r808311_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
