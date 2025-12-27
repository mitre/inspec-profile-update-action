control 'SV-224249' do
  title 'BMC IOA configuration/parameter values are not specified properly.'
  desc 'BMC IOA configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following applicable reports produced by the z/OS Data Collection:

-	IOA.RPT(SECPARM)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZIOA0040)

The following keywords will have the specified values in the BMC IOA security parameter member:

Keyword	Value
DEFMCHKI	$$IOAEDM
SECTOLI	NO
DFMI06	EXTEND
DFMI07	EXTEND
DFMI09	EXTEND
DFMI12	EXTEND
DFMI16	EXTEND
DFMI32	EXTEND
DFMI40	EXTEND
DFMI42	EXTEND
IOACLASS	IOAFAC
SAFSCLAS	SURROGAT
IOATCBS	YES'
  desc 'fix', 'The BMC IOA Systems programmer will verify that any configuration/parameters that are required to control the security of the product are properly configured and syntactically correct.  Set the standard values for the BMC IOA security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Keyword	Value
DEFMCHKI	$$IOAEDM
SECTOLI	NO
DFMI06	EXTEND
DFMI07	EXTEND
DFMI09	EXTEND
DFMI12	EXTEND
DFMI16	EXTEND
DFMI32	EXTEND
DFMI40	EXTEND
DFMI42	EXTEND
IOACLASS	IOAFAC
SAFSCLAS	SURROGAT
IOATCBS	YES'
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for ACF2'
  tag check_id: 'C-25922r518905_chk'
  tag severity: 'medium'
  tag gid: 'V-224249'
  tag rid: 'SV-224249r518907_rule'
  tag stig_id: 'ZIOAA040'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25910r518906_fix'
  tag 'documentable'
  tag legacy: ['SV-31958', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
