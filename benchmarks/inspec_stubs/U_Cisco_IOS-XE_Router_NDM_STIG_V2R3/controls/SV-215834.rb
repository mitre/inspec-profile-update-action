control 'SV-215834' do
  title 'The Cisco router must be configured to automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Review the router configuration to determine if it automatically audits account enabling. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account enabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the router to log account enabling using the following commands:

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17073r287541_chk'
  tag severity: 'medium'
  tag gid: 'V-215834'
  tag rid: 'SV-215834r531083_rule'
  tag stig_id: 'CISC-ND-000880'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-17071r287542_fix'
  tag 'documentable'
  tag legacy: ['SV-105423', 'V-96285']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
