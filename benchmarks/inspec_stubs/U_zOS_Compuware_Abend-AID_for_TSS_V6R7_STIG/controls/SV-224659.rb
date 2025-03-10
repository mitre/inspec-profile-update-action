control 'SV-224659' do
  title 'Compuware Abend-AID external security options must be specified properly.'
  desc 'Compuware Abend-AID offers external security interfaces that are controlled by parameters specified in FDBDPARM DD statement of the started task procedures.  These interfaces provide security controls for Abend-AID.  Without proper controls to ensure that security is active, the integrity of the Compuware Abend-AID System and the confidentiality of data stored on the system may be compromised.'
  desc 'check', 'Examine the Enterprise Common Components (ECC) started task procedure. (This can usually be found in the system PROCLIBs). Refer to the contents of the data set specified in the CWPARM DD statement. 

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-       PDI(ZAID0040)

Review the Member name listed.

If the following is specified for each component, this is not a finding.
Member Name: AABD00 - Abend-AID batch dump capture address space
	EXTERNAL_SECURITY_ENABLED=YES    
Member Name: AATD00 - Abend-AID CICS Transaction Dump Capture Address Space
 	EXTERNAL_SECURITY_ENABLED=YES 
Member Name: AAVW00 - Abend-AID viewing server  
	EXTERNAL_SECURITY_ENABLED=YES'
  desc 'fix', 'In the data set specified in the CWPARM DD statement from the ECC started task procedure, specify the parameter values for each component in the respective members as follows:

Member Name: AABD00 - Abend-AID batch dump capture address space
	EXTERNAL_SECURITY_ENABLED=YES    
Member Name: AATD00 - Abend-AID CICS Transaction Dump Capture Address Space
 	EXTERNAL_SECURITY_ENABLED=YES 
Member Name: AAVW00 - Abend-AID viewing server  
	EXTERNAL_SECURITY_ENABLED=YES'
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for TSS'
  tag check_id: 'C-26342r519833_chk'
  tag severity: 'medium'
  tag gid: 'V-224659'
  tag rid: 'SV-224659r519835_rule'
  tag stig_id: 'ZAID0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26330r519834_fix'
  tag 'documentable'
  tag legacy: ['SV-43205', 'V-18014']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
