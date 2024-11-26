control 'SV-225584' do
  title 'NetView Started Task name(s) is not properly identified / defined to the system ACP.'
  desc 'NetView requires a started task(s) that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

b)	Review the NetView STC/Batch ACID(s) for the following:

___	Is defined as CNMPROC for the ACID.

___	Is defined as CNMPSSI for the ACID.

___	Both are defined with Facility of STC and/or BATCH.

___	CNMPROC is defined with Master Facility of NETVIEW.

___	Both are sourced to the INTRDR.

c)	If all of the above are true, there is NO FINDING.

d)	If any of the above is untrue, this is a FINDING.'
  desc 'fix', "The Systems Programmer and IAO will ensure that the started task(s) for NetView is properly defined.

Define the started task userid CNMPROC and CNMPSSI for NetView.

Example:

TSS CRE(CNMPROC) DEPT(Dept) NAME('NetView') -
  FAC(STC) MASTFAC(NETVIEW) PASSWORD(password,0) -
  SOURCE(INTRDR)
TSS CRE(CNMPSSI) DEPT(Dept) NAME('NetView') -
  FAC(STC) PASSWORD(password,0) -
  SOURCE(INTRDR)"
  impact 0.5
  ref 'DPMS Target zOS NetView for TSS'
  tag check_id: 'C-27283r472548_chk'
  tag severity: 'medium'
  tag gid: 'V-225584'
  tag rid: 'SV-225584r472550_rule'
  tag stig_id: 'ZNETT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27271r472549_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-28615']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
