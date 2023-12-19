control 'SV-224438' do
  title 'CA MIM Resource Sharing external security options must be specified properly.'
  desc 'CA MIM Resource Sharing offers external security interfaces that are controlled by parameters specified in the MIMINIT member in the MIMPARMS DD statement of the started task procedures.  These interfaces provide security controls for CA MIM.  Without proper controls to ensure that security is active, the integrity of the CA MIM Resource Sharing System and the confidentiality of data stored on the system may be compromised.'
  desc 'check', 'Refer to the contents of MIMINIT member of the data set(s) specified in the MIMPARMS DD statement of the started task procedures.
 
Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZMIM0040)

Ensure the following CA MIM Resource Sharing parameter(s) is (are) specified in the MIMINIT member of the data set(s) specified in the MIMPARMS DD statement of the started task procedures.  If the following guidance is true, this is not a finding. 

Parameter	Value
SAFCMDAUTH	ON'
  desc 'fix', 'The systems programmer/IAO will ensure that the CA MIM Resource Sharing parameter(s) is (are) specified.  CA MIM Resource Sharing security interfaces are controlled by parameters coded in the MIMINIT member of the data set(s) specified in the MIMPARMS DD statement of the started task procedures.
 
Parameter	Value
SAFCMDAUTH	ON'
  impact 0.5
  ref 'DPMS Target zOS CA MIM for RACF'
  tag check_id: 'C-26115r519629_chk'
  tag severity: 'medium'
  tag gid: 'V-224438'
  tag rid: 'SV-224438r519631_rule'
  tag stig_id: 'ZMIM0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26103r519630_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-46150']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
