control 'SV-221605' do
  title 'Splunk Enterprise must use an SSO proxy service, F5 device, or SAML implementation to accept the DoD CAC or other smart card credential for identity management, personal authentication, and multifactor authentication.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as a primary component of layered protection for national security systems.

If the application cannot meet this requirement, the risk may be mitigated through use of an authentication server.'
  desc 'check', 'If the instance being checked is in a distributed environment and has the web interface disabled, this check is N/A.

Verify that Splunk Enterprise is configured to use the DoD CAC credential to log into the application.

If it is not configured to allow the use of the DoD CAC credential, this is a finding.'
  desc 'fix', 'Configure an SSO proxy service using Apache, IIS, F5, SAML, etc., to provide CAC credentials to Splunk Enterprise. 

Examples for Apache and F5 are provided using the supplemental documentation included in this package to be used in addition to the Splunk documentation.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23320r856022_chk'
  tag severity: 'medium'
  tag gid: 'V-221605'
  tag rid: 'SV-221605r879764_rule'
  tag stig_id: 'SPLK-CL-000045'
  tag gtitle: 'SRG-APP-000391-AU-002290'
  tag fix_id: 'F-23309r416273_fix'
  tag 'documentable'
  tag legacy: ['SV-111313', 'V-102359']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
