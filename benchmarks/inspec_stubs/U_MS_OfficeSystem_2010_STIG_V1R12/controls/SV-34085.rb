control 'SV-34085' do
  title 'Key Usage Filtering must be allowed.'
  desc 'This policy setting allows you to filter a list of digital certificates for signing Excel, PowerPoint, and Word documents, based on the Key Usage field. The Key Usage field in a certificate is used to represent a series of basic constraints about the broad types of operations that can be performed with the certificate. Key usage filtering allows you to filter the list of installed certificates that can be used for signing documents. The filtered list will appear when users attempt to select a certificate for digitally signing a document.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Signing  “Key Usage Filtering” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\general

Criteria: If the value FilterDigitalSignatureCert is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Signing  “Key Usage Filtering” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26629'
  tag rid: 'SV-34085r1_rule'
  tag stig_id: 'DTOO311 - Office System'
  tag gtitle: 'DTOO311 - Key Usage Filtering'
  tag fix_id: 'F-29915r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
