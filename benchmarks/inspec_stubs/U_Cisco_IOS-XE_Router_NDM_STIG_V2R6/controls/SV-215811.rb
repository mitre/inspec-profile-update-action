control 'SV-215811' do
  title 'The Cisco router must be configured to automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the router configuration to determine if it automatically audits account removal. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the router to log account removal using the following commands:

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17050r287472_chk'
  tag severity: 'medium'
  tag gid: 'V-215811'
  tag rid: 'SV-215811r879528_rule'
  tag stig_id: 'CISC-ND-000120'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-17048r287473_fix'
  tag 'documentable'
  tag legacy: ['SV-105341', 'V-96203']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
