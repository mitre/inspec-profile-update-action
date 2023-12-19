control 'SV-224446' do
  title 'CA VTAPE Started Task name is not properly identified/defined to the system ACP.'
  desc 'CA VTAPE requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

The CA VTAPE started task(s) and/or batch job userid(s) is defined and is assigned the RACF PROTECTED attribute.'
  desc 'fix', "The CA VTAPE system programmer and the IAO will ensure that a product's Started Task(s) is properly identified/defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

au SVTS name('CA VTAPE') owner(stc) dfltgrp(stc) nopass
au SVTSAS name('CA VTAPE') owner(stc) dfltgrp(stc) nopass"
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for RACF'
  tag check_id: 'C-26123r519680_chk'
  tag severity: 'medium'
  tag gid: 'V-224446'
  tag rid: 'SV-224446r519682_rule'
  tag stig_id: 'ZVTAR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26111r519681_fix'
  tag 'documentable'
  tag legacy: ['SV-33831', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
