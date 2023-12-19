control 'SV-95585' do
  title 'AAA Services must be configured to queue audit records locally until communication is restored when any audit processing failure occurs.'
  desc 'It is critical that when AAA Services are at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

For AAA Services, availability is an overriding concern, and so both of the following approved actions in response to an audit failure must be met:

(i) If the failure was caused by the lack of audit record storage capacity, AAA Services must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.
(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, AAA Services must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify AAA Services are configured to queue audit records locally when any audit processing failure occurs. The queuing must continue until communication is restored or until the audit records are retrieved manually. Some specific implementations may further require automatically restarting the audit service to synchronize the local audit data with the collection server.

If AAA Services are not configured to queue audit records locally until communication is restored when any audit processing failure occurs, this is a finding.'
  desc 'fix', 'Configure AAA Services to queue audit records locally until communication is restored when any audit processing failure occurs. Some specific implementations may further require automatically restarting the audit service to synchronize the local audit data with the collection server. In some cases, AAA Services may require the audit records to be retrieved manually in the event of audit failure.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80611r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80875'
  tag rid: 'SV-95585r1_rule'
  tag stig_id: 'SRG-APP-000109-AAA-000310'
  tag gtitle: 'SRG-APP-000109-AAA-000310'
  tag fix_id: 'F-87729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
