control 'SV-224509' do
  title 'IBM System Display and Search Facility (SDSF) Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'IBM System Display and Search Facility (SDSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

Verify that the userid(s) for the IBM SDSF started task(s) is (are) properly defined. If the following attributes are defined, this is not a finding.

PROTECTED'
  desc 'fix', "The ISSO working with the systems programmer will ensure the IBM SDSF Started Task(s) is properly identified and/or defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how a Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

au SDSF name('STC, SDSF') owner(stc) dfltgrp(stc) nopass –
	data('SDSF stc')"
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for RACF'
  tag check_id: 'C-26192r840219_chk'
  tag severity: 'medium'
  tag gid: 'V-224509'
  tag rid: 'SV-224509r840220_rule'
  tag stig_id: 'ZISFR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26180r840218_fix'
  tag 'documentable'
  tag legacy: ['SV-40822', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
