control 'SV-224634' do
  title 'CA VTAPE Started Task name is not properly identified/defined to the system ACP.'
  desc 'CA VTAPE requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Review each CA VTAPE STC/Batch ACID(s) for the following:

___	Defined with Facility of STC and/or BATCH for SVTS and SVTAS.

___	Is sourced to the INTRDR.'
  desc 'fix', "The CA VTAPE system programmer and the IAO will ensure that a product's Started Task(s) is properly identified/defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

TSS CREATE(SVTS) TYPE(USER) -
	NAME('CA VTAPE') DEPT(xxxx) - 
 	FAC(STC) -
	PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND
TSS CREATE(SVTSAS) TYPE(USER) -
	NAME('CA VTAPE') DEPT(xxxx) - 
 	FAC(STC) -
	PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for TSS'
  tag check_id: 'C-26317r519692_chk'
  tag severity: 'medium'
  tag gid: 'V-224634'
  tag rid: 'SV-224634r519694_rule'
  tag stig_id: 'ZVTAT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26305r519693_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-33832']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
