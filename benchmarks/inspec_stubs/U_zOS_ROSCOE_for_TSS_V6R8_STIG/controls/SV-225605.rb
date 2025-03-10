control 'SV-225605' do
  title 'ROSCOE configuration/parameter values are not specified properly.'
  desc 'Product configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'a)	Have the the product system programmer display the configuration/parameter control statements used in the current running product to define or enable security.  This information is located in the SYSIN DD statement in the JCL of the STC/Batch job.

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZROS0040)

b)	Verify the following specifications:

Keyword	Value
EXTSEC	TSS
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
  desc 'fix', 'The product system programmer will verify that any configuration / parameters that are required to control the security of the product are properly configured and syntactically correct.
 
See the required parameters below: Example

Keyword	Value
EXTSEC	TSS
ACFEXT	YES
CLLEXT	YES
JOBEXT	YES
LIBEXT	YES
MONEXT	YES
PRVEXT	YES
RPFEXT	YES
UPSEXT	YES'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for TSS'
  tag check_id: 'C-27305r520874_chk'
  tag severity: 'medium'
  tag gid: 'V-225605'
  tag rid: 'SV-225605r520876_rule'
  tag stig_id: 'ZROST040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-27293r520875_fix'
  tag 'documentable'
  tag legacy: ['SV-23714', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
