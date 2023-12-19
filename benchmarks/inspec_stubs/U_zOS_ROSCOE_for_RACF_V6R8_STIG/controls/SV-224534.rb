control 'SV-224534' do
  title 'Product configuration/parameter values are not specified properly.'
  desc 'Product configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'a)	Have the the products system programmer display the configuration/parameters control ststements used in the current runing product to define or enable security.  This information is located in the SYSIN DD statement in the JCL of the STC/Batch job.

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZROS0040)

b)	Verify the following specifications:

Keyword	Value
EXTSEC	RACF
ACFEXT	YES
CLLEXT	YES
JOBEXT	YES
LIBEXT	YES
MONEXT	YES
PRVEXT	YES
RPFEXT	YES
UPSEXT	YES

c)	If (b) above is true, there is NO FINDING.

d)	If (b) above is untrue, this is a FINDING'
  desc 'fix', 'The product systems programmer will verify that any configuration / parameters that are required to control the security of the product are properly configured and syntactically correct.
 
See the required parameters below: Example

Keyword	Value
EXTSEC	RACF
ACFEXT	YES
CLLEXT	YES
JOBEXT	YES
LIBEXT	YES
MONEXT	YES
PRVEXT	YES
RPFEXT	YES
UPSEXT	YES'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for RACF'
  tag check_id: 'C-26217r520850_chk'
  tag severity: 'medium'
  tag gid: 'V-224534'
  tag rid: 'SV-224534r520852_rule'
  tag stig_id: 'ZROSR040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26205r520851_fix'
  tag 'documentable'
  tag legacy: ['SV-23712', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
