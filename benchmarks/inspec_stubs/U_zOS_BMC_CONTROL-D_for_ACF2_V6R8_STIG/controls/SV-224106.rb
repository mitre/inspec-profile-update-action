control 'SV-224106' do
  title 'BMC CONTROL-D configuration/parameter values are not specified properly.'
  desc 'BMC CONTROL-D configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following applicable reports produced by the z/OS Data Collection:

-	IOA.RPT(SECPARM)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCTD0040)

The following keywords will have the specified values in the BMC CONTROL-D security parameter member:

Keyword	Value
DEFMCHKD	$$CTDEDM
SECTOLD	NO
DFMD01	EXTEND
DFMD04	EXTEND
DFMD08	EXTEND
DFMD19	EXTEND
DFMD23	EXTEND
DFMD24	EXTEND
DFMD26	EXTEND
DFMD27	EXTEND'
  desc 'fix', 'The BMC CONTROL-D Systems programmer will verify that any configuration/parameters that are required to control the security of the product are properly configured and syntactically correct.  Set the standard values for the BMC CONTROL-D security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Keyword	Value
DEFMCHKD	$$CTDEDM
SECTOLD	NO
DFMD01	EXTEND
DFMD04	EXTEND
DFMD08	EXTEND
DFMD19	EXTEND
DFMD23	EXTEND
DFMD24	EXTEND
DFMD26	EXTEND
DFMD27	EXTEND'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for ACF2'
  tag check_id: 'C-25779r518644_chk'
  tag severity: 'medium'
  tag gid: 'V-224106'
  tag rid: 'SV-224106r518646_rule'
  tag stig_id: 'ZCTD0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25767r518645_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-32211']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
