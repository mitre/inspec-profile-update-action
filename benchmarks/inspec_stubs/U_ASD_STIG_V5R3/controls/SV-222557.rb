control 'SV-222557' do
  title 'The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Access may be denied to authorized users if federal agency PIV credentials are not accepted.

Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

If the application is only deployed to SIPRNet, this requirement is not applicable.

If the application is not intended to be available to Federal government (non-DoD) partners this requirement is not applicable.

Ask the application administrator to demonstrate how the application is configured to allow the use of PIV credentials from other agencies.

If the application is required to provide authenticated access to Federal agencies and it does not accept a PIV, this is a finding.'
  desc 'fix', 'Configure the application to accept PIV credentials when utilizing authentication provided by Federal (Non-DoD) agencies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24227r493579_chk'
  tag severity: 'medium'
  tag gid: 'V-222557'
  tag rid: 'SV-222557r879775_rule'
  tag stig_id: 'APSC-DV-001880'
  tag gtitle: 'SRG-APP-000402'
  tag fix_id: 'F-24216r493580_fix'
  tag 'documentable'
  tag legacy: ['SV-84785', 'V-70163']
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
