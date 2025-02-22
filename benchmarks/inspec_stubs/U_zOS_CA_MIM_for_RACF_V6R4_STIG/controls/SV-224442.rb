control 'SV-224442' do
  title 'CA MIM Resource Sharing Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'CA MIM Resource Sharing requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

- RACFCMDS.RPT(LISTUSER)

Verify that the userid(s) for the CA MIM Resource Sharing started task(s) is (are) properly defined. If the following attributes are defined, this is not a finding.

PROTECTED'
  desc 'fix', "The ISSO working with the systems programmer will ensure the CA MIM Resource Sharing Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

au MIMGR name('STC, CA MIM') owner(stc) dfltgrp(stc) nopass -
	data('CA MIM')"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for RACF'
  tag check_id: 'C-26119r868492_chk'
  tag severity: 'medium'
  tag gid: 'V-224442'
  tag rid: 'SV-224442r868497_rule'
  tag stig_id: 'ZMIMR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26107r868495_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-46211']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
