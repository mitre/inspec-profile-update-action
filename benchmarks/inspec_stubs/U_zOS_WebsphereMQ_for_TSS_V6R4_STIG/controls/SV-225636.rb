control 'SV-225636' do
  title 'WebSphere MQ alternate user resources defined to MQADMIN resource class are not protected in accordance with security requirements.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	SENSITVE.RPT(WHOHMADM)

b)	For all alternate user resources (i.e., ssid.ALTERNATE.USER.alternatelogonid) defined to MQADMIN resource class, ensure access authorization restricts access to users requiring the ability to use the alternate userid.  This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access list.

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'For all alternate user resources (i.e., ssid.ALTERNATE.USER.alternateuserid) defined to MQADMIN resource class, ensure access authorization restricts access to users requiring the ability to use the alternate userid. This is difficult to determine.  However, an item for concern may be a profile with * READ specified in the access
list.

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

The following is a sample of the commands required to allow payroll server (PAYSRV1) to specify alternate userids starting with the characters PS on queue manager (QM1):

TSS ADD(USER1) FAC(QM1MSTR)
TSS PER(USER1) MQADMIN(QM1.ALTERNATE.USER.PS) 
      ACC(UPDATE) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27337r472710_chk'
  tag severity: 'medium'
  tag gid: 'V-225636'
  tag rid: 'SV-225636r472712_rule'
  tag stig_id: 'ZWMQ0057'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27325r472711_fix'
  tag 'documentable'
  tag legacy: ['V-6969', 'SV-7551']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
