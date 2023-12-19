control 'SV-224568' do
  title 'BMC CONTROL-M security exits are not installed or configured properly.'
  desc 'The BMC CONTROL-M security exits enable access authorization checking to BMC CONTROL-M commands, features, and online functionality.  If these exit(s) is (are) not in place, activities by unauthorized users may result.  BMC CONTROL-M security exit(s) interface with the ACP.  If an unauthorized exit was introduced into the operating environment, system security could be weakened or bypassed.  These exposures may result in the compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Interview the systems programmer responsible for the BMC CONTROL-M.  Determine if the site has modified the following security exit(s):

CTMSE01
CTMSE02
CTMSE08

Ensure the above security exit(s) has (have) not been modified.

If the above security exit(s) has (have) been modified, ensure that the security exit(s) has (have) been approved by the site systems programmer and the approval is on file for examination.'
  desc 'fix', 'The System programmer responsible for the BMC CONTROL-M will review the BMC CONTROL-M operating environment.  Ensure that the following security exit(s) is (are) installed properly.  Determine if the site has modified the following security exit(s):

CTMSE01
CTMSE02
CTMSE08

Ensure that the security exit(s) has (have) not been modified.

If the security exit(s) has (have) been modified, ensure the security exit(s) has (have) been checked as to not violate any security integrity within the system and approval documentation is on file.'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for TSS'
  tag check_id: 'C-26251r518767_chk'
  tag severity: 'medium'
  tag gid: 'V-224568'
  tag rid: 'SV-224568r518769_rule'
  tag stig_id: 'ZCTM0060'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26239r518768_fix'
  tag 'documentable'
  tag legacy: ['SV-32017', 'V-17985']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
