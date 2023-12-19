control 'SV-224579' do
  title 'BMC CONTROL-D security exits are not installed or configured properly.'
  desc 'The BMC CONTROL-D security exits enable access authorization checking to BMC CONTROL-D commands, features, and online functionality.  If these exit(s) is (are) not in place, activities by unauthorized users may result.  BMC CONTROL-D security exit(s) interface with the ACP.  If an unauthorized exit was introduced into the operating environment, system security could be weakened or bypassed.  These exposures may result in the compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Interview the systems programmer responsible for the BMC CONTROL-D.  Determine if the site has modified the following security exit(s):

CTDSE01
CTDSE04
CTDSE08
CTDSE19
CTDSE24
CTDSE28

Ensure the above security exit(s) has (have) not been modified.

If the above security exit(s) has (have) been modified, ensure that the security exit(s) has (have) been approved by the site systems programmer and the approval is on file for examination.'
  desc 'fix', 'The System programmer responsible for the BMC CONTROL-D will review the BMC CONTROL-D operating environment.  Ensure that the following security exit(s) is (are) installed properly.  Determine if the site has modified the following security exit(s):

CTDSE01
CTDSE04
CTDSE08
CTDSE19
CTDSE24
CTDSE28

Ensure that the security exit(s) has (have) not been modified.

If the security exit(s) has (have) been modified, ensure the security exit(s) has (have) been checked as to not violate any security integrity within the system and approval documentation is on file.'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for TSS'
  tag check_id: 'C-26262r518692_chk'
  tag severity: 'medium'
  tag gid: 'V-224579'
  tag rid: 'SV-224579r518694_rule'
  tag stig_id: 'ZCTD0060'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26250r518693_fix'
  tag 'documentable'
  tag legacy: ['V-17985', 'SV-32015']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
