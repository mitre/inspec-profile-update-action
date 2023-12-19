control 'SV-224294' do
  title 'Compuware Abend-AID Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'Compuware Abend-AID requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

Verify that the logonid(s) for the Compuware Abend-AID started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

STC'
  desc 'fix', "The IAO working with the systems programmer will ensure the Compuware Abend-AID Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

SET LID
insert AAVIEWER stc name('STC, Compuware Abend-AID Viewer')
insert BDCAS stc name('STC, Compuware Abend-AID')
insert TDCAS stc name('STC, Compuware Abend-AID for CICS')"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for ACF2'
  tag check_id: 'C-25967r519809_chk'
  tag severity: 'medium'
  tag gid: 'V-224294'
  tag rid: 'SV-224294r519811_rule'
  tag stig_id: 'ZAIDA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25955r519810_fix'
  tag 'documentable'
  tag legacy: ['SV-43174', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
