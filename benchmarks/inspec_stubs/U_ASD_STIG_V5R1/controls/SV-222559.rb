control 'SV-222559' do
  title 'The application must accept FICAM-approved third-party credentials.'
  desc "FICAM establishes a federated identity framework for the Federal Government. FICAM provides Government-wide services for common Identity, Credential and Access Management (ICAM) requirements.  The FICAM Trust Framework Solutions (TFS) is the federated identity framework for the U.S. federal government.
 The TFS is a process by which Industry Trust Frameworks (The codification of requirements for credentials and their issuance, privacy and security requirements, as well as auditing qualifications and processes) are evaluated and assessed for potential use by the Government.  

A Trust Framework that is comparable to federal standards is adopted through this process, which allows Federal Government Relying Parties (Federal Government web sites or RP's) to trust Credential Service Providers a.k.a. Identity Providers that have been assessed under that particular trust framework.  This allows federal government relying parties to trust such credentials at their approved assurance levels. 

This requirement only applies to applications that are intended to be accessible to non-federal government agencies and other partners through FICAM. 

Third-party credentials are those credentials issued by non-federal government entities approved by the Federal Identity, Credential, and Access Management (FICAM) Trust Framework Solutions initiative."
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

If the application is only deployed to SIPRNet, this requirement is not applicable.

If the application is not intended to be available to Federal government partners this requirement is not applicable.

Ask the application administrator to demonstrate how the application is configured to allow the use of third-party credentials, verify the third-party credentials are FICAM approved.

If the application does not accept FICAM approved credentials when accepting third-party credentials, this is a finding.'
  desc 'fix', 'Configure applications  intended to be accessible to non-federal government agencies to use FICAM-approved third-party credentials.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24229r493585_chk'
  tag severity: 'medium'
  tag gid: 'V-222559'
  tag rid: 'SV-222559r508029_rule'
  tag stig_id: 'APSC-DV-001900'
  tag gtitle: 'SRG-APP-000404'
  tag fix_id: 'F-24218r493586_fix'
  tag 'documentable'
  tag legacy: ['V-70167', 'SV-84789']
  tag cci: ['CCI-002011']
  tag nist: ['IA-8 (2)']
end
