control 'SV-224610' do
  title 'BMC Mainview for z/OS Started Task name is not properly identified and/or defined to the system ACP.'
  desc 'BMC Mainview for z/OS requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Review each BMC Mainview for z/OS STC/Batch ACID(s) for the following:

___	Defined with Facility of STC, BBI3 (the TSS FACILITY Matrix Table entry defined for this product), and/or BATCH for MV$CAS, MV$PAS, and MV$MVS.

___	Defined with Master Facility of BBI3 (the TSS FACILITY Matrix Table entry defined for this product) for MV$CAS and MV$PAS.

___	Is sourced to the INTRDR.'
  desc 'fix', "The BMC Mainview for z/OS system programmer and the IAO will ensure that a product's Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

TSS CREATE(MV$CAS) TYPE(USER) -
	NAME('CAS, BMC Mainview for z/OS') DEPT(xxxx) - 
 	FAC(STC,BBI3) -
	MASTFAC(BBI3) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND
TSS CREATE(MV$PAS) TYPE(USER) -
	NAME('PAS, BMC Mainview for z/OS') DEPT(xxxx) - 
 	FAC(STC,BBI3) -
	MASTFAC(BBI3) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND
TSS CREATE(MV$MVS) TYPE(USER) -
	NAME('MVS, BMC Mainview for z/OS') DEPT(xxxx) - 
 	FAC(STC,BBI3) -
	PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for TSS'
  tag check_id: 'C-26293r519007_chk'
  tag severity: 'medium'
  tag gid: 'V-224610'
  tag rid: 'SV-224610r519009_rule'
  tag stig_id: 'ZMVZT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26281r519008_fix'
  tag 'documentable'
  tag legacy: ['SV-33840', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
