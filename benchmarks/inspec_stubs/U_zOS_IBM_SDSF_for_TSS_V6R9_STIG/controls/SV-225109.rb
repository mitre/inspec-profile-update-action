control 'SV-225109' do
  title 'IBM System Display and Search Facility (SDSF) Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'IBM System Display and Search Facility (SDSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Verify that the ACID(s) for the IBM SDSF started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

FACILITY(STC, BATCH)
PASSWORD(xxxxxxxx,0)
SOURCE(INTRDR)
NOSUSPEND'
  desc 'fix', "The ISSO working with the systems programmer will ensure the IBM SDSF Started Task(s) is properly identified and/or defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how a Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

TSS CREATE(SDSF) TYPE(USER) -
	NAME('STC, SDSF') DEPT(xxxx) -
	FAC(STC,BATCH) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for TSS'
  tag check_id: 'C-26808r840207_chk'
  tag severity: 'medium'
  tag gid: 'V-225109'
  tag rid: 'SV-225109r840209_rule'
  tag stig_id: 'ZISFT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26796r840208_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-40823']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
