control 'SV-224574' do
  title 'BMC CONTROL-M Started Task name is not properly identified / defined to the system ACP.'
  desc 'BMC CONTROL-M requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Review each BMC CONTROL-M STC/Batch ACID(s) for the following:

___	Defined with Facility of STC and/or BATCH.

___	Defined with Master Facility of CONTROLM.

___	Is sourced to the INTRDR.'
  desc 'fix', "The BMC CONTROL-M system programmer and the IAO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

TSS CREATE(CONTROLM) TYPE(USER) -
	NAME('*STC* for IOA') DEPT(xxxx) - 
 	FAC(STC) -
	MASTFAC(CONTROLM) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for TSS'
  tag check_id: 'C-26257r518785_chk'
  tag severity: 'medium'
  tag gid: 'V-224574'
  tag rid: 'SV-224574r518787_rule'
  tag stig_id: 'ZCTMT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26245r518786_fix'
  tag 'documentable'
  tag legacy: ['SV-32072', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
