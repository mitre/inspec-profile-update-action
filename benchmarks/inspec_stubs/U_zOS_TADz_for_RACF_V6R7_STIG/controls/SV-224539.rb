control 'SV-224539' do
  title 'Tivoli Asset Discovery for z/OS (TADz) Started Task name(s) must be properly identified / defined to the system ACP.'
  desc 'Tivoli Asset Discovery for z/OS (TADz) requires a started task(s) that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system Access Control Program (ACP), it allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

If the userid(s) for the TADz started task is defined to the security database, there is NO FINDING.

If the userid(s) for the TADz started task is not defined to the security database, this is a FINDING.'
  desc 'fix', "The Systems Programmer and ISSO will ensure that the started task for TADz is properly defined.

Define the started task for TADz.

Example:

au tadzmon name('stc, tivoli AD') nopass -
dfltgrp(stc) owner(stc) -
data('stc for tivoli asset discovery')"
  impact 0.5
  ref 'DPMS Target zOS TADz for RACF'
  tag check_id: 'C-26222r520904_chk'
  tag severity: 'medium'
  tag gid: 'V-224539'
  tag rid: 'SV-224539r520906_rule'
  tag stig_id: 'ZTADR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26210r520905_fix'
  tag 'documentable'
  tag legacy: ['SV-28554', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
