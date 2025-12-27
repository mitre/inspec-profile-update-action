control 'SV-224408' do
  title 'BMC CONTROL-O configuration/parameter values are not specified properly.'
  desc 'BMC CONTROL-O configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following applicable reports produced by the z/OS Data Collection:

-	IOA.RPT(CTOPARM)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCTO0041)

The following keywords will have the specified values in the BMC CONTROL-O security parameter member:

Keyword	Value
RUNTDFT	OWNER
RUNTCACH	100
AUTOMLOG	V'
  desc 'fix', 'The BMC CONTROL-O Systems programmer will verify that any configuration/parameters that are required to control the security of the product are properly configured and syntactically correct.  Set the standard values for the BMC CONTROL-O security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Keyword	Value
RUNTDFT	OWNER
RUNTCACH	100
AUTOMLOG	V'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for RACF'
  tag check_id: 'C-26085r518839_chk'
  tag severity: 'medium'
  tag gid: 'V-224408'
  tag rid: 'SV-224408r518841_rule'
  tag stig_id: 'ZCTO0041'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26073r518840_fix'
  tag 'documentable'
  tag legacy: ['V-22689', 'SV-32006']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
