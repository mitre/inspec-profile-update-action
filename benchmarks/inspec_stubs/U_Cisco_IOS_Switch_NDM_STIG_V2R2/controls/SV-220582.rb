control 'SV-220582' do
  title 'The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Review the Cisco switch configuration to verify that it generates audit records of configuration changes. The configuration example below will log all configuration changes:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If the Cisco switch is not configured to generate audit records of configuration changes, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to log all configuration changes as shown in the example below:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22297r507792_chk'
  tag severity: 'medium'
  tag gid: 'V-220582'
  tag rid: 'SV-220582r521267_rule'
  tag stig_id: 'CISC-ND-000330'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-22286r507793_fix'
  tag 'documentable'
  tag legacy: ['SV-110393', 'V-101289']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
