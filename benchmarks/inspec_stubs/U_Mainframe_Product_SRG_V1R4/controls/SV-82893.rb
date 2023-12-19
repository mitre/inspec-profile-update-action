control 'SV-82893' do
  title 'The Mainframe Product must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is not configured to map the authenticated identity to the individual user or group account for PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to map the authenticated identity to the individual user or group account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68403'
  tag rid: 'SV-82893r1_rule'
  tag stig_id: 'SRG-APP-000177-MFP-000244'
  tag gtitle: 'SRG-APP-000177-MFP-000244'
  tag fix_id: 'F-74519r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
