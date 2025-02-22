control 'SV-233202' do
  title 'The container platform must accept Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Controlling access to the container platform and its components is paramount in having a secure and stable system. Validating users is the first step in controlling the access. Users may be validated by the overall container platform or they may be validated by each component. It is essential to accept PIV credentials from other federal agencies and eliminate the possibility of access being denied to authorized users.

PIV credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.'
  desc 'check', 'Review the documentation and configuration to determine if the container platform accepts PIV credentials from other federal agencies. 

If the container platform does not accept other federal agency PIV credentials, this is a finding.'
  desc 'fix', 'Configure the container platform to accept PIV credentials from other federal agencies.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36138r601093_chk'
  tag severity: 'medium'
  tag gid: 'V-233202'
  tag rid: 'SV-233202r879775_rule'
  tag stig_id: 'SRG-APP-000402-CTR-000970'
  tag gtitle: 'SRG-APP-000402'
  tag fix_id: 'F-36106r601094_fix'
  tag 'documentable'
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
