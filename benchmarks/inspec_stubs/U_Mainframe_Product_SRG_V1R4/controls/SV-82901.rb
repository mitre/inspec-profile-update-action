control 'SV-82901' do
  title 'The Mainframe Product must accept Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Access may be denied to authorized users if federal agency PIV credentials are not accepted. 

PIV credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is not configured to accept PIV credentials from other federal agencies, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to accept PIV credentials from other federal agencies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68411'
  tag rid: 'SV-82901r1_rule'
  tag stig_id: 'SRG-APP-000402-MFP-000249'
  tag gtitle: 'SRG-APP-000402-MFP-000249'
  tag fix_id: 'F-74527r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
