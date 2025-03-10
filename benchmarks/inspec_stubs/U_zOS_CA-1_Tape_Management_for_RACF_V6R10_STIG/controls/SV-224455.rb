control 'SV-224455' do
  title 'CA 1 Tape Management Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'CA 1 Tape Management requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

- RACFCMDS.RPT(LISTUSER)

Verify that the userid(s) for the CA 1 Tape Management started task(s) is (are) properly defined. If the following attributes are defined, this is not a finding.

PROTECTED'
  desc 'fix', "The ISSO working with the systems programmer will ensure the CA 1 Tape Management Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

au TMSINIT name('STC, CA 1 Tape Management') owner(stc) dfltgrp(stc) nopass -
	data('Start CA1 TMS')
au CTS name('STC, CA 1 Common Tape System') owner(stc) dfltgrp(stc) nopass -
	data(' CA Common Tape Service for CA1 - used to create tape labels')"
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for RACF'
  tag check_id: 'C-26132r868311_chk'
  tag severity: 'medium'
  tag gid: 'V-224455'
  tag rid: 'SV-224455r868313_rule'
  tag stig_id: 'ZCA1R030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26120r868312_fix'
  tag 'documentable'
  tag legacy: ['SV-40080', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
