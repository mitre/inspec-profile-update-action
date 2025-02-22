control 'SV-224557' do
  title 'WebSphere MQ resource classes are not properly actived for security checking by the ACP.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to ensure the classes have been made ACTIVE under RACF will prevent RACF from enforcing security rules.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'Refer to the following reports produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)
-	DSMON.RPT(RACCDT) - Alternate list of active resource classes

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZWMQ0049)

Ensure the following WebSphere MQ resource classes are active:

GMQADMIN
GMQNLIST
GMQPROC
GMQQUEUE
MQADMIN
MQCMDS
MQCONN
MQNLIST
MQPROC
MQQUEUE

For V7.0.0 and above:

GMXADMIN
GMXNLIST
GMXPROC
GMXQUEUE
GMXTOPIC
MXADMIN
MXNLIST
MXPROC
MXQUEUE
MXTOPIC

NOTE:	If both MQADMIN and MXADMIN resource classes are not active, no security checking is performed.'
  desc 'fix', 'The IAO will ensure that all WebSphere MQ resources are active and properly defined.

Ensure the following WebSphere MQ resource classes are active:

GMQADMIN
GMQNLIST
GMQPROC
GMQQUEUE
MQADMIN
MQCMDS
MQCONN
MQNLIST
MQPROC
MQQUEUE

For V7.0.0 and above:

GMXADMIN
GMXNLIST
GMXPROC
GMXQUEUE
GMXTOPIC
MXADMIN
MXNLIST
MXPROC
MXQUEUE
MXTOPIC

NOTE:	If both MQADMIN and MXADMIN resource classes are not active, no security checking is performed.

The follow sample contains commands to active the required classes:

SETR CLASSACT(MQADMIN MQCMDS MQCONN)
SETR CLASSACT(MQNLIST MQPROC MQQUEUE)
SETR CLASSACT(MXADMIN MXNLIST MXPROC MXQUEUE)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26240r521030_chk'
  tag severity: 'medium'
  tag gid: 'V-224557'
  tag rid: 'SV-224557r521032_rule'
  tag stig_id: 'ZWMQ0049'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26228r521031_fix'
  tag 'documentable'
  tag legacy: ['V-6959', 'SV-7534']
  tag cci: ['CCI-000213', 'CCI-002358']
  tag nist: ['AC-3', 'AC-25']
end
