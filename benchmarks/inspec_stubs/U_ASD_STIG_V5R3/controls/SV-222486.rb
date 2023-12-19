control 'SV-222486' do
  title 'The application must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'It is critical that when the application is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the application must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the application must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Review system documentation and interview application administrator for details regarding logging configuration.

Identify application shut down capability regarding audit processing failure events.  Locate and verify application logging settings that specify the application will halt processing on detected audit failure.

If ISSO approval to continue operating and not shut down the application upon an audit failure exists and is documented, validate the application is configured as follows:

If logging locally and the failure is attributed to a lack of disk space:

Ensure the application is configured to overwrite the oldest logs first so as to maintain the most up to date audit events in the event of an audit failure.

When logging centrally:

Ensure the application is configured to locally spool/queue audit events in the event an audit failure is detected with the centralized system.

If the application does not shut down processing when an audit failure is detected, or if the application does not take steps needed to ensure audit events are not lost due to audit failure, this is a finding.'
  desc 'fix', 'Configure the application to cease processing if the audit system fails or configure the application to continue logging in a manner that compensates for the audit failure.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24156r493366_chk'
  tag severity: 'medium'
  tag gid: 'V-222486'
  tag rid: 'SV-222486r879571_rule'
  tag stig_id: 'APSC-DV-001120'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-24145r493367_fix'
  tag 'documentable'
  tag legacy: ['SV-84077', 'V-69455']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
