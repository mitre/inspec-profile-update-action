control 'SV-205576' do
  title 'The Mainframe Product must accept FICAM-approved third-party credentials.'
  desc 'Access may be denied to legitimate users if FICAM-approved third-party credentials are not accepted. 

This requirement typically applies to organizational information systems that are accessible to non-federal government agencies and other partners. This allows federal government relying parties to trust such credentials at their approved assurance levels.

Third-party credentials are those credentials issued by non-federal government entities approved by the Federal Identity, Credential, and Access Management (FICAM) Trust Framework Solutions initiative.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is not configured to accept FICAM-approved third-party credentials, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to accept FICAM-approved third-party credentials.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5842r299955_chk'
  tag severity: 'medium'
  tag gid: 'V-205576'
  tag rid: 'SV-205576r851342_rule'
  tag stig_id: 'SRG-APP-000404-MFP-000251'
  tag gtitle: 'SRG-APP-000404'
  tag fix_id: 'F-5842r299956_fix'
  tag 'documentable'
  tag legacy: ['SV-82905', 'V-68415']
  tag cci: ['CCI-002011']
  tag nist: ['IA-8 (2)']
end
