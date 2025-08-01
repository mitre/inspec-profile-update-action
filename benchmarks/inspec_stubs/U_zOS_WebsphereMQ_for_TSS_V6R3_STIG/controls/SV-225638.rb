control 'SV-225638' do
  title 'WebSphere MQ command resources defined to MQCMDS resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(WHOHMCMD)

b)	For all command resources (i.e., ssid.command) defined to MQCMDS resource class, ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

1)	Access authorization restricts access to the appropriate personnel as designated in the Websphere MQ COMMAND SECURITY CONTROLS Table in the z/OS STIG Addendum.
2)	All command access is logged as designated in the Websphere MQ COMMAND SECURITY CONTROLS Table in the z/OS STIG Addendum.

c)	If both of the items in (b) are true, there is NO FINDING.

d)	If either item in (b) is untrue, this is a FINDING.'
  desc 'fix', 'Command security validates userids authorized to issue MQSeries/WebSphere MQ commands.  Command security will be active, and all profiles will be defined to the MQCMDS class.

For all command resources (i.e., ssid.command) defined to MQCMDS resource class, ensure the following items are in effect:

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

    1) Access authorization restricts access to the appropriate personnel as designated in the table entitled "Websphere MQ Command Security Controls " in the zOS STIG Addendum. 

2) All command access is logged as designated in the table entitled "Websphere MQ Command Security Controls " in the zOS STIG Addendum.

The following is a sample of the commands required to allow a systems programming group (SYS1) to issue the command CLEAR QLOCAL in subsystem QM1:

TSS ADD(SYS1) FAC(QM1MSTR)
TSS PER(SYS1) MQCMDS(QM1.CLEAR.LOCAL) ACC(ALTER)
		ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27339r472716_chk'
  tag severity: 'medium'
  tag gid: 'V-225638'
  tag rid: 'SV-225638r472718_rule'
  tag stig_id: 'ZWMQ0059'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27327r472717_fix'
  tag 'documentable'
  tag legacy: ['SV-7555', 'V-6973']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
