control 'SV-224531' do
  title 'ROSCOE Started Task name is not properly identified / defined to the system ACP.'
  desc 'Products that require a started task will require that the started task be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

b)	If the Product started task(s) or Product batch job userid(s) is defined and is assigned the RACF PROTECTED attribute, there is NO FINDING.

c)	If the above is untrue, than this is a FINDING.'
  desc 'fix', "The ROSCOE system programmer and the IAO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

au roscoe name('stc, roscoe') owner(stc) dfltgrp(stc) nopass"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for RACF'
  tag check_id: 'C-26214r520841_chk'
  tag severity: 'medium'
  tag gid: 'V-224531'
  tag rid: 'SV-224531r520843_rule'
  tag stig_id: 'ZROSR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26202r520842_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-23710']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
