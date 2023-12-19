control 'SV-222560' do
  title 'The application must conform to FICAM-issued profiles.'
  desc 'FICAM establishes a federated identity framework for the Federal Government. FICAM provides Government-wide services for common Identity, Credential, and Access Management (ICAM) requirements.  The FICAM Trust Framework Solutions (TFS) is the federated identity framework for the U.S. federal government.
 The TFS is a process by which Industry Trust Frameworks (The codification of requirements for credentials and their issuance, privacy and security requirements, as well as auditing qualifications and processes) are evaluated and assessed for potential use by the Government.  

This requirement only applies to applications that are intended to be accessible to non-federal government agencies and other partners or non-organizational (non-DoD) users.

Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0, OpenID 2.0 or other protocols such as the FICAM backend Attribute Exchange.

This requirement addresses open identity management standards.  More information regarding these standards is available by pointing your web browser to: info.idmanagement.gov/2012/10/what-are-ficam-technical-profiles-and.html'
  desc 'check', "Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

If the application is only deployed to SIPRNet, this requirement is not applicable.

If the application is not intended to be available to Federal government partners this requirement is not applicable.

This requirement applies to DoD service providers who are relying parties of external (Federal Government) identity providers.
 
Ask the application administrator to demonstrate how the application conforms to FICAM issued profiles such as SAML or OPENID.  

If the application is designed to be a service provider utilizing an external identify provider and doesn't conform to FICAM-issued profiles, this is a finding."
  desc 'fix', 'Configure the application to conform to FICAM-issued technical profiles when providing services that rely on external (Federal Government) identity providers.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24230r493588_chk'
  tag severity: 'medium'
  tag gid: 'V-222560'
  tag rid: 'SV-222560r508029_rule'
  tag stig_id: 'APSC-DV-001910'
  tag gtitle: 'SRG-APP-000405'
  tag fix_id: 'F-24219r493589_fix'
  tag 'documentable'
  tag legacy: ['V-70169', 'SV-84791']
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
