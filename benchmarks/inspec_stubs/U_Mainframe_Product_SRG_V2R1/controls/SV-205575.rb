control 'SV-205575' do
  title 'The Mainframe Product must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Inappropriate access may be granted to unauthorized users if federal agency PIV credentials are not electronically verified. 

PIV credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations. 

If the Mainframe Product is not configured to electronically verify PIV credentials from other federal agencies, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to electronically verify PIV credentials from other federal agencies.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5841r299952_chk'
  tag severity: 'medium'
  tag gid: 'V-205575'
  tag rid: 'SV-205575r851341_rule'
  tag stig_id: 'SRG-APP-000403-MFP-000250'
  tag gtitle: 'SRG-APP-000403'
  tag fix_id: 'F-5841r299953_fix'
  tag 'documentable'
  tag legacy: ['SV-82903', 'V-68413']
  tag cci: ['CCI-002010']
  tag nist: ['IA-8 (1)']
end
