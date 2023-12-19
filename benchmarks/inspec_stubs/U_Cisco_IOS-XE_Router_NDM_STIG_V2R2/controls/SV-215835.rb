control 'SV-215835' do
  title 'The Cisco router must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. The configuration example below will log all commands entered from the command line interface as well as log all configuration changes.

hostname R1
!
logging userinfo
!
…
…
…
archive
 log config
 logging enable
!

Note: The logging userinfo global configuration command will generate a log when a user increases his or her privilege level.

If the Cisco router is not configured to log all commands entered from the command line interface as well as log all configuration changes, this is a finding.'
  desc 'fix', 'Configure the Cisco router to log all commands entered from the command line interface as well as log all configuration changes as shown in the following example:

R1(config)#logging userinfo
R1(config)#archive
R1(config-archive)#log config
R1(config-archive-log-cfg)#logging enable
R1(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17074r287544_chk'
  tag severity: 'medium'
  tag gid: 'V-215835'
  tag rid: 'SV-215835r531083_rule'
  tag stig_id: 'CISC-ND-000940'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-17072r287545_fix'
  tag 'documentable'
  tag legacy: ['SV-105429', 'V-96291']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
