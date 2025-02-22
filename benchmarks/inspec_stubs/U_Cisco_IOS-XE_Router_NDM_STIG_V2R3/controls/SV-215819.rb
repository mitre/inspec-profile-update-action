control 'SV-215819' do
  title 'The Cisco router must be configured to generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. The configuration example below will log all configuration changes.

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If the Cisco router is not configured to generate audit records of configuration changes, this is a finding.'
  desc 'fix', 'Configure the Cisco router to log all configuration changes as shown in the example below.

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17058r287496_chk'
  tag severity: 'medium'
  tag gid: 'V-215819'
  tag rid: 'SV-215819r531083_rule'
  tag stig_id: 'CISC-ND-000330'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-17056r287497_fix'
  tag 'documentable'
  tag legacy: ['SV-105365', 'V-96227']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
