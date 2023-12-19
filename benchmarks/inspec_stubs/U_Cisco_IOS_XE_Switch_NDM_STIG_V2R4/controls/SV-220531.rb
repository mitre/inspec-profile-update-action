control 'SV-220531' do
  title 'The Cisco switch must be configured to protect audit information from unauthorized modification.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement.

Step 1: If persistent logging is enabled as shown in the example below, go to Step 2. Otherwise, this requirement is not applicable.

logging persistent url disk0:/logfile size 134217728 filesize 16384

Step 2: Verify that the switch is not configured with a privilege level other than "15" to allow access to the file system as shown in the example below:

file privilege 10 

Note: The default privilege level required for access to the file system is "15"; hence, the command file privilege "15" will not be shown in the configuration.

If the switch is configured with a privilege level other than "15" to allow access to the file system, this is a finding.'
  desc 'fix', 'If persistent logging is enabled, configure the switch to only allow administrators with privilege level "15" access to the file system as shown in the example below:

SW4(config)#file privilege 15'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22246r508537_chk'
  tag severity: 'medium'
  tag gid: 'V-220531'
  tag rid: 'SV-220531r508539_rule'
  tag stig_id: 'CISC-ND-000380'
  tag gtitle: 'SRG-APP-000119-NDM-000236'
  tag fix_id: 'F-22235r508538_fix'
  tag 'documentable'
  tag legacy: ['SV-110517', 'V-101413']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
