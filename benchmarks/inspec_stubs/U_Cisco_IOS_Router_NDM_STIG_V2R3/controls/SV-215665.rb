control 'SV-215665' do
  title 'The Cisco router must be configured to automatically audit account disabling actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the router configuration to determine if it automatically audits account disabling. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account disabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the router to log account disabling using the following commands:

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16859r285957_chk'
  tag severity: 'medium'
  tag gid: 'V-215665'
  tag rid: 'SV-215665r521266_rule'
  tag stig_id: 'CISC-ND-000110'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-16857r285958_fix'
  tag 'documentable'
  tag legacy: ['SV-105157', 'V-96019']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
