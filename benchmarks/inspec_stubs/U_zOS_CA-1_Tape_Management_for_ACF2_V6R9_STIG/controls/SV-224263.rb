control 'SV-224263' do
  title 'CA 1 Tape Management Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'CA 1 Tape Management requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

Verify that the logonid(s) for the CA 1 Tape Management started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

STC'
  desc 'fix', "The IAO working with the systems programmer will ensure the CA 1 Tape Management Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

SET LID
insert TMSINIT stc name('STC, CA 1 Tape Management')
insert CTS stc name('STC, CA 1 Common Tape System')"
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for ACF2'
  tag check_id: 'C-25936r519473_chk'
  tag severity: 'medium'
  tag gid: 'V-224263'
  tag rid: 'SV-224263r519475_rule'
  tag stig_id: 'ZCA1A030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25924r519474_fix'
  tag 'documentable'
  tag legacy: ['SV-40079', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
