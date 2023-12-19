control 'SV-224123' do
  title 'BMC CONTROL-O configuration/parameter values are not specified properly.'
  desc 'BMC CONTROL-O configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following applicable reports produced by the z/OS Data Collection:

-	IOA.RPT(SECPARM)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCTO0040)

The following keywords will have the specified values in the BMC CONTROL-O security parameter member:

Keyword	Value
DEFMCHKO	$$CTOEDM
SECTOLO	NO
DFMO01	EXTEND
DFMO02	EXTEND
DFMO03	EXTEND
DFMO04	EXTEND
DFMO08	EXTEND
DFMO10	PROD (new for 6.3.xx)
DFMO15	EXTEND'
  desc 'fix', 'The BMC CONTROL-O Systems programmer will verify that any configuration/parameters that are required to control the security of the product are properly configured and syntactically correct.  Set the standard values for the BMC CONTROL-O security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Keyword	Value
DEFMCHKO	$$CTOEDM
SECTOLO	NO
DFMO01	EXTEND
DFMO02	EXTEND
DFMO03	EXTEND
DFMO04	EXTEND
DFMO08	EXTEND
DFMO10	PROD (new for 6.3.xx)
DFMO15	EXTEND'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for ACF2'
  tag check_id: 'C-25796r518815_chk'
  tag severity: 'medium'
  tag gid: 'V-224123'
  tag rid: 'SV-224123r518817_rule'
  tag stig_id: 'ZCTO0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25784r518816_fix'
  tag 'documentable'
  tag legacy: ['SV-32004', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
