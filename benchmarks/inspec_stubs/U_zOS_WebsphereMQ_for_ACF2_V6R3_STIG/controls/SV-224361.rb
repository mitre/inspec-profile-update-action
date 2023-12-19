control 'SV-224361' do
  title 'Websphere MQ switch profiles must be properly defined to the MQADMIN class.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)       Refer to the following report produced by the OS/390 & z/OS Data Collection:

-       MQSRPT(ssid)

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

Automated Analysis requires Additional Analysis.
Automated Analysis
Refer to the following report produced by the OS/390 & z/OS Data Collection:

-       PDI(ZWMQ0051)

b)       Review the Security switches identified in response to the DISPLAY SECURITY command in each ssid report(s).       If the all of the following switches specify ON, there is NO FINDING.

SUBSYSTEM
CONNECTION
COMMAND
CONTEXT
ALTERNATE USER
PROCESS
NAMELIST
QUEUE
COMMAND RESOURCES

c)       If SUBSYSTEM specifies OFF, this is a FINDING with a severity of Category I.

d)       If any of the other above switches specify OFF (other than the exception mentioned below), this is a FINDING downgrade the severity to a Category II.

e)       If COMMAND RESOURCE Security switch specify OFF, there is NO FINDING.

NOTE:       At the discretion of the IAO, COMMAND RESOURCE Security switch may specify OFF, by defining ssid.NO.CMD.RESC.CHECKS in the TYPE(MQA).'
  desc 'fix', 'The IAO will ensure that all Switch Profiles do not have the resource ssid.NO defined to the MQADMIN resource class with the exception of ssid.NO.CMD.RESC.CHECKS.

ssid is the queue manager name (a.k.a., subsystem identifier).

Ensure that all of the following switches specify ON.

SUBSYSTEM
CONNECTION
COMMAND
CONTEXT
ALTERNATE USER
PROCESS
NAMELIST
QUEUE
COMMAND RESOURCES

Example:

$KEY(ssid) TYPE(MQA)
ALTERNATE.USER.- UID(*) PREVENT
CONTEXT.- UID(*) PREVENT
RESLEVEL UID(*) PREVENT
- UID(*) PREVENT

NOTE:	At the discretion of the IAO, COMMAND RESOURCE Security switch may specify OFF, by defining ssid.NO.CMD.RESC.CHECKS in the TYPE(MQA).

Example:

$KEY(ssid) TYPE(MQA)
NO.CMD.RESC.CHECKS UID(*) PREVENT'
  impact 0.7
  ref 'DPMS Target zOS WebsphereMQ for ACF2'
  tag check_id: 'C-26038r520982_chk'
  tag severity: 'high'
  tag gid: 'V-224361'
  tag rid: 'SV-224361r520984_rule'
  tag stig_id: 'ZWMQ0051'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26026r520983_fix'
  tag 'documentable'
  tag legacy: ['SV-7261', 'V-6960']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
