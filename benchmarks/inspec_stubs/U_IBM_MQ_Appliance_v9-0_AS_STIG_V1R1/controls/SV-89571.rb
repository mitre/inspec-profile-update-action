control 'SV-89571' do
  title 'The MQ Appliance messaging server must uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed messaging servers and components, the decisions regarding the validation of identification claims may be made by services separate from the messaging server. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions. Note: Following are the cipher specs available for MQ: https://ibm.biz/BdrJGp'
  desc 'check', 'Check that TLS mutual authentication configuration is correct by using "DISPLAY" commands. 

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

To display available SVRCONN channels details, enter:
DIS CHANNEL(*) CHLTYPE(SVRCONN)

Note the names of SVRCONN channels (client channels). 

Display values for each channel:
DIS CHANNEL([name of SVRCONN channel])

Confirm that the parameter "SSLCIPH" specifies a FIPS approved cipher spec and that the value of "SSLAUTH" is set to "REQUIRED".

MQ cipher specs are available here: https://ibm.biz/BdrJGp Utilize a FIPS approved cipher when specifying SSLCIPH.

If either the "SSLCIPH" or "SSLAUTH" value for each channel is not correct, this is a finding.'
  desc 'fix', 'Run the fix for each affected queue manager and each affected channel. 

To access the MQ Appliance enter:
mqcli
runmqsc [queue name]

ALTER CHANNEL([channel name] CHLTYPE(SVRCONN) TRPTYPE(TCP) 
SSLCIPH([Use FIPS Approved cipher specs only]) SSLCAUTH(REQUIRED)

Enter "end" to exit runmqsc mode.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74897'
  tag rid: 'SV-89571r1_rule'
  tag stig_id: 'MQMH-AS-001000'
  tag gtitle: 'SRG-APP-000158-AS-000108'
  tag fix_id: 'F-81513r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
