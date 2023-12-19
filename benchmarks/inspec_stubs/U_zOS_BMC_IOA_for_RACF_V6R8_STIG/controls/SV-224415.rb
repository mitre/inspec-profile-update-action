control 'SV-224415' do
  title 'BMC IOA security exits are not installed or configured properly.'
  desc 'The BMC IOA security exits enable access authorization checking to BMC IOA commands, features, and online functionality.  If these exit(s) is (are) not in place, activities by unauthorized users may result.  BMC IOA security exit(s) interface with the ACP.  If an unauthorized exit was introduced into the operating environment, system security could be weakened or bypassed.  These exposures may result in the compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Interview the systems programmer responsible for the BMC IOA.  Determine if the site has modified the following security exit(s):

IOASE06
IOASE07
IOASE09
IOASE12
IOASE16
IOASE32
IOASE40
IOASE42

Ensure the above security exit(s) has (have) not been modified.

If the above security exit(s) has (have) been modified, ensure that the security exit(s) has (have) been approved by the site systems programmer and the approval is on file for examination.'
  desc 'fix', 'The System programmer responsible for the BMC IOA will review the BMC IOA operating environment.  Ensure that the following security exit(s) is (are) installed properly.  Determine if the site has modified the following security exit(s):

IOASE06
IOASE07
IOASE09
IOASE12
IOASE16
IOASE32
IOASE40
IOASE42

Ensure that the security exit(s) has (have) not been modified.

If the security exit(s) has (have) been modified, ensure the security exit(s) has (have) been checked as to not violate any security integrity within the system and approval documentation is on file.'
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for RACF'
  tag check_id: 'C-26092r518908_chk'
  tag severity: 'medium'
  tag gid: 'V-224415'
  tag rid: 'SV-224415r518910_rule'
  tag stig_id: 'ZIOA0060'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26080r518909_fix'
  tag 'documentable'
  tag legacy: ['V-17985', 'SV-32018']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
