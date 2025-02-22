control 'SV-225637' do
  title 'WebSphere MQ context resources defined to the MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	SENSITVE.RPT(WHOHMADM)

b)	For all context resources (i.e., ssid.CONTEXT) defined to the MQADMIN resource class, ensure access authorization restricts access to users requiring the ability to pass or set identity and/or origin data for a message.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'For all context resources (i.e., ssid.CONTEXT) defined to the MQADMIN resource class, ensure access authorization restricts access to users requiring the ability to pass or
set identity and/or origin data for a message. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

The following is a sample of the commands required to allow a systems programming group (SYS1) to offload and reload messages for queue manager (QM1):

TSS ADD(SYS1) FAC(QM1MSTR)
TSS PER(SYS1) MQADMIN(QM1.CONTEXT) ACC(UPDATE) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27338r472713_chk'
  tag severity: 'medium'
  tag gid: 'V-225637'
  tag rid: 'SV-225637r472715_rule'
  tag stig_id: 'ZWMQ0058'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27326r472714_fix'
  tag 'documentable'
  tag legacy: ['SV-7553', 'V-6971']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
