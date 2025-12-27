control 'SV-224335' do
  title 'Quest NC-Pass Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'Quest NC-Pass requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

Verify that the logonid(s) for the Quest NC-Pass started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

STC
MUSASS
NO-SMC
MUSUPDT'
  desc 'fix', "The IAO working with the systems programmer will ensure the Quest NC-Pass Started Task(s) is properly identified and/or defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

SET LID
insert NCPASS stc name('STC, Quest NC-Pass') musass no-smc musupdt"
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for ACF2'
  tag check_id: 'C-26012r520796_chk'
  tag severity: 'medium'
  tag gid: 'V-224335'
  tag rid: 'SV-224335r520798_rule'
  tag stig_id: 'ZNCPA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26000r520797_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-40872']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
