control 'SV-224429' do
  title 'BMC MAINVIEW for z/OS configuration/parameter values are not specified properly.'
  desc 'BMC MAINVIEW for z/OS configuration/parameters controls the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the Configuration Location dataset and member specified in the z/OS Dialog Management Procedures for BMC MAINVIEW for z/OS. 

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZMVZ0040)

The following keywords will have the specified values in the BMC MAINVIEW for z/OS security parameter member:

Statement(values)
ESMTYPE(AUTO|RACF)'
  desc 'fix', 'The BMC MAINVIEW for z/OS Systems programmer will verify that any configuration/parameters that are required to control the security of the product are properly configured and syntactically correct.  Set the standard values for the BMC MAINVIEW for z/OS security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Statement(values)
ESMTYPE(AUTO|RACF)'
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for RACF'
  tag check_id: 'C-26106r518995_chk'
  tag severity: 'medium'
  tag gid: 'V-224429'
  tag rid: 'SV-224429r518997_rule'
  tag stig_id: 'ZMVZR040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26094r518996_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-37807']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
