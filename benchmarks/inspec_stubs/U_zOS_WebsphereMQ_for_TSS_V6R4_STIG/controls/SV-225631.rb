control 'SV-225631' do
  title 'WebSphere MQ MQCONN Class resources must be protected properly.'
  desc 'WebSphere MQ resources allow for the control of administrator functions, connections, commands, queues, processes, and namelists.  Some resources provide the ability to disable or bypass security checking.  Failure to properly protect WebSphere MQ resources may result in unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of system services, applications, and customer data.'
  desc 'check', 'a)       Refer to the following report produced by the TSS Data Collection:

-       SENSITVE.RPT(WHOHMCON)

b)       Review the following connection resources defined to the MQCONN resource class:

Resource       Authorized Users
ssid.BATCH       TSO and batch job ACIDs
ssid.CICS       CICS region ACIDs
ssid.IMS       IMS region ACIDs
ssid.CHIN       Channel initiator ACIDs

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

c)       For all connection resources defined to the MQCONN resource class, ensure the following items are in effect:

1)       Access authorization restricts access to the appropriate users as indicated in (b) above.
2)       All access FAILUREs are logged.

d)       If all of the items in (c) are true, there is NO FINDING.

e)       If any item in (c) is untrue, this is a FINDING.'
  desc 'fix', 'Review the following connection resources defined to the MQCONN resource class:

Resource       Authorized Users
ssid.BATCH       TSO and batch job ACIDs
ssid.CICS       CICS region ACIDs
ssid.IMS       IMS region ACIDs
ssid.CHIN       Channel initiator ACIDs

NOTE:       ssid is the queue manager name (a.k.a., subsystem identifier).

c) For all connection resources defined to the MQCONN resource class, ensure the following items are in effect:

1) Access authorization restricts access to the appropriate users as indicated in (b) above.
2) All access FAILUREs are logged.

The following is a sample of the commands required to allow a batch user (USER1) to connect to a queue manager (QM1):

TSS ADD(USER1) FAC(QM1MSTR)
TSS PER(USER1) MQCONN(QM1.BATCH) ACC(READ)'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27332r472695_chk'
  tag severity: 'medium'
  tag gid: 'V-225631'
  tag rid: 'SV-225631r855253_rule'
  tag stig_id: 'ZWMQ0052'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27320r472696_fix'
  tag 'documentable'
  tag legacy: ['SV-7542', 'V-6962']
  tag cci: ['CCI-002234', 'CCI-000213']
  tag nist: ['AC-6 (9)', 'AC-3']
end
