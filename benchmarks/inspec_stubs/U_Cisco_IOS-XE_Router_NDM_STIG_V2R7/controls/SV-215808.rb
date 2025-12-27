control 'SV-215808' do
  title 'The Cisco router must be configured to automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the router configuration to determine if it automatically audits account creation. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the router to log account creation using the following commands:

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17047r287463_chk'
  tag severity: 'medium'
  tag gid: 'V-215808'
  tag rid: 'SV-215808r879525_rule'
  tag stig_id: 'CISC-ND-000090'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-17045r287464_fix'
  tag 'documentable'
  tag legacy: ['SV-105335', 'V-96197']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
