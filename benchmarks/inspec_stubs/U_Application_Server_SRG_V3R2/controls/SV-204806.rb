control 'SV-204806' do
  title 'The application server must accept Personal Identity Verification (PIV) credentials from other federal agencies to access the management interface.'
  desc 'Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.  PIV credentials are only used in an unclassified environment.

Access may be denied to authorized users if federal agency PIV credentials are not accepted to access the management interface.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server accepts PIV credentials from other federal agencies to access the management interface.

If the application server does not accept other federal agency PIV credentials to access the management interface, this is a finding.'
  desc 'fix', 'Configure the application server to accept PIV credentials from other federal agencies to access the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4926r283059_chk'
  tag severity: 'medium'
  tag gid: 'V-204806'
  tag rid: 'SV-204806r508029_rule'
  tag stig_id: 'SRG-APP-000402-AS-000247'
  tag gtitle: 'SRG-APP-000402'
  tag fix_id: 'F-4926r283060_fix'
  tag 'documentable'
  tag legacy: ['V-57515', 'SV-71791']
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
