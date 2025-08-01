control 'SV-90879' do
  title 'CounterACT must use an Enterprise Manager or other high availability solution to ensure redundancy in case of audit failure in this critical network access control and security service.'
  desc 'It is critical that when the network element is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

1. If the failure was caused by the lack of audit record storage capacity, the network element must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2. If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the network element must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

A NAC is an essential security service and should not be shut down in the event of an audit failure. Redundancy and rollover features of the CounterACT enterprise or a high availability solution should be leveraged. Load balancing and redundancy is a function of the CounterAct enterprise architecture by default.'
  desc 'check', 'Examine architecture documentation. Verify CounterACT implementation includes an Enterprise Manager combined with Appliances to ensure redundancy. It is also acceptable to have two appliances configured for redundancy. 

If CounterACT implementation does not include an Enterprise Manager combined with Appliances or a high availability solution to ensure redundancy, this is a finding.'
  desc 'fix', 'Design and install CounterACT implementation to include an Enterprise Manager combined with one or more Appliances or a high availability solution. The Appliances will associate with the enterprise Manager or the high availability solution.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75877r2_chk'
  tag severity: 'medium'
  tag gid: 'V-76191'
  tag rid: 'SV-90879r2_rule'
  tag stig_id: 'CACT-AG-000026'
  tag gtitle: 'SRG-NET-000089-ALG-000055'
  tag fix_id: 'F-82829r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
