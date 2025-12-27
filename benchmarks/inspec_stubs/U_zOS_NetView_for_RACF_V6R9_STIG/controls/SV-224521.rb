control 'SV-224521' do
  title 'NetView Started Task name(s) is not properly identified / defined to the system ACP.'
  desc 'NetView requires a started task(s) that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

b)	If the NetView started task(s) is defined and is assigned the RACF PROTECTED attribute, there is NO FINDING.

c)	If the above is untrue, than this is a FINDING.'
  desc 'fix', "The NetView system programer and the IAO will ensure that the product's Started Task(s) is properly Identified / defined to the System ACP. 

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

au cnmpssi name('stc, netview') nopass dfltgrp(stc) -
owner(stc) data('netview subsystem interface')
au cnmproc name('stc, netview') nopass dfltgrp(stc) -
owner(stc) data('netview')"
  impact 0.5
  ref 'DPMS Target zOS NetView for RACF'
  tag check_id: 'C-26204r520781_chk'
  tag severity: 'medium'
  tag gid: 'V-224521'
  tag rid: 'SV-224521r520783_rule'
  tag stig_id: 'ZNETR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26192r520782_fix'
  tag 'documentable'
  tag legacy: ['SV-28614', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
