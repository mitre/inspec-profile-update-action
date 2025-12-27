control 'SV-233051' do
  title 'The container platform must take appropriate action upon an audit failure.'
  desc 'It is critical that when the container platform is at risk of failing to process audit logs as required that it take action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

Because availability of the services provided by the container platform, approved actions in response to an audit failure are as follows:

(i) If the failure was caused by the lack of audit record storage capacity, the container platform must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the container platform must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Review the configuration settings to determine how the container platform components are configured for audit failures. When the audit failure is due to the lack of audit record storage, the container platform must continue generating audit records, restarting services if necessary, and overwrite the oldest audit records in a first-in-first-out manner. 

If the audit failure is due to a communication to a centralized collection server, the container platform must queue audit records locally until communication is restored or the records are retrieved manually.  

If the container platform is not configured to handle audit failures appropriately, this is a finding.'
  desc 'fix', 'Configure the container platform to continue generating audit records overwriting oldest audit records in a first-in-first-out manner when the failure is due to a lack of audit record storage.   When the audit failure is due to a communication to a centralized collection server, configure the container platform to queue audit records locally until communication is restored or the records are retrieved manually.  If other actions are to be taken for audit record failures, the actions and rationale must be documented in the system security plan and risk acceptance approvals must be obtained.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35987r601636_chk'
  tag severity: 'medium'
  tag gid: 'V-233051'
  tag rid: 'SV-233051r601637_rule'
  tag stig_id: 'SRG-APP-000109-CTR-000215'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-35955r601861_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
