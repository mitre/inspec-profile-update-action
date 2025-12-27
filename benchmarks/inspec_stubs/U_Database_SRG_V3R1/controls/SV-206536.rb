control 'SV-206536' do
  title 'The DBMS must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the DBMS must continue generating audit records, if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the DBMS must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations.'
  desc 'check', 'If the application owner has determined that the need for system availability does not outweigh the need for a complete audit trail, this is not applicable (NA).

Review DBMS, OS, or third-party logging application settings and/or documentation to determine whether the system is capable of continuing to generate audit records, overwriting the oldest existing records, in the case of an auditing failure. If it is not, this is a finding.

If the system is capable of continuing to generate audit records upon audit failure but is not configured to do so, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of continuing to generate audit records upon audit failure.

Configure the system to continue to generate audit records, overwriting the oldest existing records, in the case of an auditing failure.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6796r291276_chk'
  tag severity: 'medium'
  tag gid: 'V-206536'
  tag rid: 'SV-206536r617447_rule'
  tag stig_id: 'SRG-APP-000109-DB-000321'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-6796r291277_fix'
  tag 'documentable'
  tag legacy: ['SV-72491', 'V-58061']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
