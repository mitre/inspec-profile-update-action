control 'SV-224281' do
  title 'CA VTAPE Started Task name is not properly identified/defined to the system ACP.'
  desc 'CA VTAPE requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

Insure that the logonids(s) for the CA VTAPE started task(s) includes the following:

STC
NO-SMC'
  desc 'fix', "The CA VTAPE system programmer and the IAO will ensure that a product's Started Task(s) is properly identified/defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

Example:

SET LID
INSERT SVTS STC NO-SMC
INSERT SVTSAS STC NO-SMC"
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for ACF2'
  tag check_id: 'C-25954r519671_chk'
  tag severity: 'medium'
  tag gid: 'V-224281'
  tag rid: 'SV-224281r519673_rule'
  tag stig_id: 'ZVTAA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25942r519672_fix'
  tag 'documentable'
  tag legacy: ['SV-33830', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
