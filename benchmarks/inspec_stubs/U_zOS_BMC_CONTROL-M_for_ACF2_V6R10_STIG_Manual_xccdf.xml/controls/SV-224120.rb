control 'SV-224120' do
  title 'BMC CONTROL-M configuration/parameter values must be specified properly.'
  desc 'BMC CONTROL-M configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following applicable reports produced by the z/OS Data Collection:

-	IOA.RPT(SECPARM)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCTM0040)

The following keywords will have the specified values in the BMC CONTROL-M security parameter member:

Keyword	Value
DEFMCHKM	$$CTMEDM
SECTOLM	NO
DFMM01	EXTEND
DFMM02	EXTEND
DFMM08	EXTEND
SAFJCARD	U
MSUBCHK	NO'
  desc 'fix', 'Configure the standard values for the BMC CONTROL-M security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Keyword	Value
DEFMCHKM	$$CTMEDM
SECTOLM	NO
DFMM01	EXTEND
DFMM02	EXTEND
DFMM08	EXTEND
SAFJCARD	U
MSUBCHK	NO'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for ACF2'
  tag check_id: 'C-25793r518737_chk'
  tag severity: 'medium'
  tag gid: 'V-224120'
  tag rid: 'SV-224120r518739_rule'
  tag stig_id: 'ZCTMA040'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25781r518738_fix'
  tag 'documentable'
  tag legacy: ['SV-31975', 'V-18014']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
