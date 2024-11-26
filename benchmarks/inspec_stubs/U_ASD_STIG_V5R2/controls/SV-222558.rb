control 'SV-222558' do
  title 'The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Inappropriate access may be granted to unauthorized users if federal agency PIV credentials are not electronically verified.

Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

If the application is only deployed to SIPRNet, this requirement is not applicable.

If the application is not intended to be available to Federal government (non-DoD) partners this requirement is not applicable.

Ask the application administrator to demonstrate how the application is configured to verify the PIV credentials from other agencies when they are presented as an authentication token.

If the application is required to provide authenticated access to Federal agencies and it does not verify the PIV, this is a finding.'
  desc 'fix', 'Configure the application to verify the PIV credentials presented when utilizing authentication provided by Federal (Non-DoD) agencies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24228r493582_chk'
  tag severity: 'medium'
  tag gid: 'V-222558'
  tag rid: 'SV-222558r849468_rule'
  tag stig_id: 'APSC-DV-001890'
  tag gtitle: 'SRG-APP-000403'
  tag fix_id: 'F-24217r493583_fix'
  tag 'documentable'
  tag legacy: ['SV-84787', 'V-70165']
  tag cci: ['CCI-002010']
  tag nist: ['IA-8 (1)']
end
