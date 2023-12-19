control 'SV-225635' do
  title 'WebSphere MQ Namelist resources are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	SENSITVE.RPT(WHOHMNLI)

b)	For all namelist resources (i.e., ssid.namelist) defined to MQNLIST resource class, ensure access authorization restricts access to users requiring the ability to make namelist inquiries.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'For all namelist resources (i.e., ssid.namelist) defined to MQNLIST resource class, ensure access authorization restricts access to users requiring the ability to make
namelist inquiries. This is difficult to determine. However, an item for concern may be a profile with * READ specified in the access list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

The following is a sample of the commands required to allow a user (USER1) to inquire on namelist TST1 on queue manager (QM1):

TSS ADD(USER1) FAC(QM1MSTR)
TSS PER(USER1) MQNLIST(QM1.TST1.) ACC(READ) 
      ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27336r472707_chk'
  tag severity: 'medium'
  tag gid: 'V-225635'
  tag rid: 'SV-225635r472709_rule'
  tag stig_id: 'ZWMQ0056'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27324r472708_fix'
  tag 'documentable'
  tag legacy: ['V-6967', 'SV-7549']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
