control 'SV-224286' do
  title 'CL/SuperSession Started Task name is not properly identified / defined to the system ACP.'
  desc 'CL/SuperSession requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

b)	If the logonid for the CL/SUPERSESSION started task includes MUSASS and NO-SMC, there is NO FINDING.

c)	If the logonid for the CL/SUPERSESSION started task does not include MUSASS and/or NO-SMC, this is a FINDING.'
  desc 'fix', 'The Systems Programmer and IAO will ensure that the started task for CL/SuperSession is properly defined.

Review all session manager security parameters and control options for compliance. Develop a plan of action and implement the changes as specified.

Define the started task userid KLS for CL/SuperSession.

Example:

INSERT KLS NAME(STC, CL/SuperSession) MUSASS NO-SMC STC'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for ACF2'
  tag check_id: 'C-25959r519728_chk'
  tag severity: 'medium'
  tag gid: 'V-224286'
  tag rid: 'SV-224286r519730_rule'
  tag stig_id: 'ZCLSA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25947r519729_fix'
  tag 'documentable'
  tag legacy: ['SV-28590', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
