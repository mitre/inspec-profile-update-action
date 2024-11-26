control 'SV-224667' do
  title 'IBM CSSMTP Started Task name is not properly identified and/or defined to the system ACP.'
  desc 'IBM CSSMTP requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Review each IBM CSSMTP STC/Batch ACID(s) for the following:

___	Defined with Facility of STC (the TSS FACILITY Matrix Table entry defined for this product), and/or BATCH for CSSMTP.

___	Is sourced to the INTRDR.'
  desc 'fix', "The IBM CSSMTP system programmer and the IAO will ensure that a product's Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

TSS CREATE(CSSMTP) TYPE(USER) -
	NAME('IBM CSSMTP') DEPT(xxxx) - 
 	FAC(STC) -
	PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS CSSMTP for TSS'
  tag check_id: 'C-26356r519872_chk'
  tag severity: 'medium'
  tag gid: 'V-224667'
  tag rid: 'SV-224667r519874_rule'
  tag stig_id: 'ZSMTT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26344r519873_fix'
  tag 'documentable'
  tag legacy: ['SV-37481', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
