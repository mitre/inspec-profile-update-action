control 'SV-224577' do
  title 'BMC CONTROL-M configuration/parameter values must be specified properly.'
  desc 'BMC CONTROL-M configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following applicable reports produced by the z/OS Data Collection:

-       IOA.RPT(SECPARM)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-       PDI(ZCTM0040)

The following keywords will have the specified values in the BMC CONTROL-M security parameter member:

Keyword       Value
DEFMCHKM       $$CTMEDM
SECTOLM       NO
DFMM01       EXTEND
DFMM02       EXTEND
DFMM08       EXTEND
TSSJCARD       U
MSUBCHK       NO'
  desc 'fix', 'The BMC CONTROL-M Systems programmer will verify that any configuration/parameters that are required to control the security of the product are properly configured and syntactically correct.  Set the standard values for the BMC CONTROL-M security parameters for the specific ACP environment along with additional IOA security parameters with standard values as documented below.

Keyword	Value
DEFMCHKM	$$CTMEDM
SECTOLM	NO
DFMM01	EXTEND
DFMM02	EXTEND
DFMM08	EXTEND
TSSJCARD	U
MSUBCHK	NO'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for TSS'
  tag check_id: 'C-26260r518794_chk'
  tag severity: 'medium'
  tag gid: 'V-224577'
  tag rid: 'SV-224577r518796_rule'
  tag stig_id: 'ZCTMT040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26248r518795_fix'
  tag 'documentable'
  tag legacy: ['SV-31980', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
