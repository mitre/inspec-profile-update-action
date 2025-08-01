control 'SV-225634' do
  title 'WebSphere MQ Process resources are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	SENSITVE.RPT(WHOHMPRO)

b)	For all process resources (i.e., ssid.processname) defined to MQPROC resource class, ensure access authorization restricts access to users requiring the ability to make process inquiries.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'For all process resources (i.e., ssid.processname) defined to MQPROC resource class, ensure access authorization restricts access to users requiring the ability to make
process inquiries. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

The following is a sample of the commands required to allow a user (USER1) to inquire on processes beginning with the letter V on queue manager (QM1):

TSS ADD(USER1) FAC(QM1MSTR)
TSS PER(USER1) MQPROC(QM1.V) ACC(READ) 
      ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27335r472704_chk'
  tag severity: 'medium'
  tag gid: 'V-225634'
  tag rid: 'SV-225634r472706_rule'
  tag stig_id: 'ZWMQ0055'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27323r472705_fix'
  tag 'documentable'
  tag legacy: ['SV-7547', 'V-6966']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
