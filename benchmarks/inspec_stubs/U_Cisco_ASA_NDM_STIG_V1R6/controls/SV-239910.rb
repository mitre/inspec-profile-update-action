control 'SV-239910' do
  title 'The Cisco ASA must be configured to generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log full-text recording of privileged commands.

If the Cisco ASA is not configured to generate audit records containing the full-text recording of privileged commands, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43143r666091_chk'
  tag severity: 'medium'
  tag gid: 'V-239910'
  tag rid: 'SV-239910r879569_rule'
  tag stig_id: 'CASA-ND-000320'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-43102r666092_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
