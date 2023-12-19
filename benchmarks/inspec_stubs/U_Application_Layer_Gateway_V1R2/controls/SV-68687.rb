control 'SV-68687' do
  title 'The ALG must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'It is critical that when the network element is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

1) If the failure was caused by the lack of audit record storage capacity, the network element must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the network element must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify the ALG shuts down by default upon audit failure (unless availability is an overriding concern).

If the ALG does not shut down by default upon audit failure (unless availability is an overriding concern), this is a finding.'
  desc 'fix', 'Configure the ALG to shut down by default upon audit failure (unless availability is an overriding concern).'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55057r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54441'
  tag rid: 'SV-68687r1_rule'
  tag stig_id: 'SRG-NET-000089-ALG-000055'
  tag gtitle: 'SRG-NET-000089-ALG-000055'
  tag fix_id: 'F-59295r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
