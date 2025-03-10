control 'SV-89401' do
  title 'The MQ Appliance messaging server must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'Non-repudiation of actions taken is required in order to messaging service application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Typical messaging server actions requiring non-repudiation will be related to application deployment among developers/users and administrative actions taken by admin personnel.'
  desc 'check', 'Establish an SSH command line session as an admin user.

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

To run the "runmqsc [queue mgr name]" command for each running queue manager enter:
DIS QMGR EVENT

A list of all events will be displayed along with an indication if event logging is enabled. The events are as follows:

Authority: AUTHOREV, Inhibit: INHIBITEV, Local: LOCALEV, Remote: REMOTEEV, Start and stop: STRSTPEV, Performance: PERFMEV, Command: CMDEV, Channel: CHLEV, Channel auto definition: CHADEV, SSL: SSLEV, Configuration: CONFIGEV

If AUTHOREV event logging is not enabled, this is a finding.'
  desc 'fix', 'To access the MQ Appliance CLI, enter:
mqcli

runmqsc [queue mgr name]
ALTER QMGR [AUTHOREV](ENABLED)

To exit the MQ Appliance CLI, enter:
end'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74727'
  tag rid: 'SV-89401r1_rule'
  tag stig_id: 'MQMH-AS-000010'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag fix_id: 'F-81341r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
