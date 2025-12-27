control 'SV-239903' do
  title 'The Cisco ASA must be configured to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged. To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands that include the name of the user. The ASA also logs the name of the user entering the enable command.

If logging of administrator activity is not configured, this is a finding.'
  desc 'fix', 'Configure the ASA to log administrator activity as shown below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43136r666070_chk'
  tag severity: 'medium'
  tag gid: 'V-239903'
  tag rid: 'SV-239903r879554_rule'
  tag stig_id: 'CASA-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-43095r666071_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
