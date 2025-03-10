control 'SV-89559' do
  title 'The MQ Appliance messaging server must protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing operationally-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. To reduce the possibility or effect of a DoS, the messaging server must employ defined security safeguards. These safeguards will be determined by the placement of the messaging server and the type of applications being hosted within the messaging server framework.

There are many examples of technologies that exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy or clustering, may reduce the susceptibility to some DoS attacks.

Note: IBM recommends that neither MQ server nor the MQ Appliance be placed in the DMZ where it could be vulnerable to DoS attacks. IBM recommends that this protection be provided by a firewall: https://ibm.biz/BdraMj

For internal queue managers, You can restrict the total number of incoming connections by setting the MaxConnectionThreads property: https://ibm.biz/BdraMZ

'
  desc 'check', 'Obtain documentation that specifies operational limits from system admin. Check the "SVRCONN" channels of each queue manager to confirm that "MAXINST" and "MAXINSTC" values are set to a value that reflects operational requirements.

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

To run the "runmqsc [queue mgr name]" command for each running queue manager identified, enter:
runmqsc [queue mgr name]

To display available SVRCONN channels details, enter:
DIS CHANNEL(*) CHLTYPE(SVRCONN) 

Display values for each channel:
DIS CHANNEL(Channel Name)

If the value of either "MAXINST" or "MAXINSTC" is greater than the organization-defined limit, this is a finding.'
  desc 'fix', "For each queue manager's server connection (SVRCONN) channel(s):

To access the MQ Appliance CLI, enter:
mqcli

runmqsc <queue manager name> >>

To display available SVRCONN channels, enter:
DIS CHANNEL(*) CHLTYPE(SVRCONN)

ALTER CHANNEL(<svrconn channel name>) CHLTYPE(SVRCONN) 
MAXINST(max allowed channel instances)
MAXINSTC(max allowed channels for same client: less than MAXINST)
end"
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74885'
  tag rid: 'SV-89559r1_rule'
  tag stig_id: 'MQMH-AS-000650'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-81501r1_fix'
  tag satisfies: ['SRG-APP-000435-AS-000163', 'SRG-APP-000001-AS-000001']
  tag 'documentable'
  tag cci: ['CCI-000054', 'CCI-002385']
  tag nist: ['AC-10', 'SC-5 a']
end
