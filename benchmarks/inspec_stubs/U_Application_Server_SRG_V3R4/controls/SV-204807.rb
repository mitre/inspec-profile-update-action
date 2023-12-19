control 'SV-204807' do
  title 'The application server must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies to access the management interface.'
  desc 'Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials.  PIV credentials are only used in an unclassified environment.

If PIV credentials are not electronically verified before accessing the management interface, unauthorized users may gain access to the system and data the user has not been granted access to.'
  desc 'check', 'The CAC is the standard DoD authentication token;the PIV is the standard authentication token used by federal/civilian agencies.
 
If access to the application server is limited to DoD personnel accessing the system via CAC; and PIV access is not warranted or allowed as per the system security plan, the PIV requirement is NA.

Review the application server documentation and configuration to determine if the application server electronically verifies PIV credentials from other federal agencies to access the management interface.

If the application server does not electronically verify other federal agency PIV credentials to access the management interface, this is a finding.'
  desc 'fix', 'Configure the unclassified application server to electronically verify PIV credentials from other federal agencies before granting access to the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4927r283062_chk'
  tag severity: 'medium'
  tag gid: 'V-204807'
  tag rid: 'SV-204807r879776_rule'
  tag stig_id: 'SRG-APP-000403-AS-000248'
  tag gtitle: 'SRG-APP-000403'
  tag fix_id: 'F-4927r283063_fix'
  tag 'documentable'
  tag legacy: ['SV-71793', 'V-57517']
  tag cci: ['CCI-002010']
  tag nist: ['IA-8 (1)']
end
