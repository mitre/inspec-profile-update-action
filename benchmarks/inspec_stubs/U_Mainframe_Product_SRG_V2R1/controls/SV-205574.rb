control 'SV-205574' do
  title 'The Mainframe Product must accept Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Access may be denied to authorized users if federal agency PIV credentials are not accepted. 

PIV credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is not configured to accept PIV credentials from other federal agencies, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to accept PIV credentials from other federal agencies.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5840r299949_chk'
  tag severity: 'medium'
  tag gid: 'V-205574'
  tag rid: 'SV-205574r851340_rule'
  tag stig_id: 'SRG-APP-000402-MFP-000249'
  tag gtitle: 'SRG-APP-000402'
  tag fix_id: 'F-5840r299950_fix'
  tag 'documentable'
  tag legacy: ['SV-82901', 'V-68411']
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
