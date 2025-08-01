control 'SV-225601' do
  title 'ROSCOE Started Task name is not properly identified / defined to the system ACP.'
  desc 'Products that require a started task will require that the started task be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

b)	Review each ROSCOE STC/Batch ACID(s) for the following:

___	Is defined with Facility of STC and/or BATCH.

___	Is defined with Master Facility of ROSCOE.

___	Is sourced to the INTRDR.

c)	If all of the above are true, there is NO FINDING.

d)	If any of the above is untrue, this is a FINDING.'
  desc 'fix', "The ROSCOE system programmer and the IAO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

TSS CREATE(ROSCOE) TYPE(USER) -
	NAME('*STC* for ROSCO') DEPT(xxxx) - 
                     FAC(STC) -
	MASTFAC(ROSCOE) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for TSS'
  tag check_id: 'C-27301r520862_chk'
  tag severity: 'medium'
  tag gid: 'V-225601'
  tag rid: 'SV-225601r520864_rule'
  tag stig_id: 'ZROST030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27289r520863_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-23711']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
