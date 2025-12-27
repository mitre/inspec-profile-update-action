control 'SV-220532' do
  title 'The Cisco switch must be configured to protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit data.'
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
  tag check_id: 'C-22247r508540_chk'
  tag severity: 'medium'
  tag gid: 'V-220532'
  tag rid: 'SV-220532r879578_rule'
  tag stig_id: 'CISC-ND-000390'
  tag gtitle: 'SRG-APP-000120-NDM-000237'
  tag fix_id: 'F-22236r508541_fix'
  tag 'documentable'
  tag legacy: ['SV-110519', 'V-101415']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
