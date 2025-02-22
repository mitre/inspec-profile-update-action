control 'SV-224584' do
  title 'BMC CONTROL-D Started Task name is not properly identified / defined to the system ACP.'
  desc 'BMC CONTROL-D requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Review each BMC CONTROL-D STC/Batch ACID(s) for the following:

___	Defined with Facility of STC and/or BATCH.

___	Defined with Master Facility of CONTROLD.

___	Is sourced to the INTRDR.'
  desc 'fix', "The BMC CONTROL-D system programmer and the IAO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

TSS CREATE(CONTROLD) TYPE(USER) -
	NAME('*STC* for CONTROL-D') DEPT(xxxx) - 
 	FAC(STC) -
	MASTFAC(CONTROLD) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for TSS'
  tag check_id: 'C-26267r518707_chk'
  tag severity: 'medium'
  tag gid: 'V-224584'
  tag rid: 'SV-224584r518709_rule'
  tag stig_id: 'ZCTDT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26255r518708_fix'
  tag 'documentable'
  tag legacy: ['SV-32069', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
