control 'SV-224591' do
  title 'BMC CONTROL-O security exits are not installed or configured properly.'
  desc 'The BMC CONTROL-O security exits enable access authorization checking to BMC CONTROL-O commands, features, and online functionality.  If these exit(s) is (are) not in place, activities by unauthorized users may result.  BMC CONTROL-O security exit(s) interface with the ACP.  If an unauthorized exit was introduced into the operating environment, system security could be weakened or bypassed.  These exposures may result in the compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Interview the systems programmer responsible for the BMC CONTROL-O.  Determine if the site has modified the following security exit(s):

CTOSE01
CTOSE02
CTOSE03
CTOSE04
CTOSE08
CTOSE10
CTOSE15

Ensure the above security exit(s) has (have) not been modified.

If the above security exit(s) has (have) been modified, ensure that the security exit(s) has (have) been approved by the site systems programmer and the approval is on file for examination.'
  desc 'fix', 'The System programmer responsible for the BMC CONTROL-O will review the BMC CONTROL-O operating environment.  Ensure that the following security exit(s) is (are) installed properly.  Determine if the site has modified the following security exit(s):

CTOSE01
CTOSE02
CTOSE03
CTOSE04
CTOSE08
CTOSE10
CTOSE15

Ensure that the security exit(s) has (have) not been modified.

If the security exit(s) has (have) been modified, ensure the security exit(s) has (have) been checked as to not violate any security integrity within the system and approval documentation is on file.'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for TSS'
  tag check_id: 'C-26274r518866_chk'
  tag severity: 'medium'
  tag gid: 'V-224591'
  tag rid: 'SV-224591r518868_rule'
  tag stig_id: 'ZCTO0060'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26262r518867_fix'
  tag 'documentable'
  tag legacy: ['V-17985', 'SV-32016']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
