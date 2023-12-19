control 'SV-224653' do
  title 'CL/SuperSession Started Task name is not properly identified / defined to the system ACP.'
  desc 'CL/SuperSession requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

b)	Review the CL/SuperSession STC/Batch ACID(s) for the following:

___	Is defined as KLS for the ACID.

___	Is defined with Facility of STC and/or BATCH.

___	Is defined with Master Facility of KLS.

___	Is sourced to the INTRDR.

c)	If all of the above are true, there is NO FINDING.

d)	If any of the above is untrue, this is a FINDING.'
  desc 'fix', "The Systems Programmer and IAO will ensure that the started task for CL/SuperSession is properly defined.

Review all session manager security parameters and control options for compliance. Develop a plan of action and implement the changes as specified.

Define the started task userid KLS for CL/SuperSession.

Example:

TSS CRE(KLS) DEPT(Dept) NAME('CL/SuperSession STC') -
  FAC(STC) MASTFAC(KLS) PASSWORD(password,0) -
  SOURCE(INTRDR)"
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for TSS'
  tag check_id: 'C-26336r519776_chk'
  tag severity: 'medium'
  tag gid: 'V-224653'
  tag rid: 'SV-224653r519778_rule'
  tag stig_id: 'ZCLST030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26324r519777_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-28592']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
