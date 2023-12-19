control 'SV-82757' do
  title 'The Mainframe Product must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'It is critical that when the application is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the application must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the application must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine configuration settings for audit failure parameters.

If Mainframe Product does not shut down by default in the event of audit processing failure, this is a finding.

Note: This depends on whether availability is an overriding concern.'
  desc 'fix', 'Configure the Mainframe Product to shut down by default upon audit failure (unless availability is an overriding concern).'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68267'
  tag rid: 'SV-82757r1_rule'
  tag stig_id: 'SRG-APP-000109-MFP-000155'
  tag gtitle: 'SRG-APP-000109-MFP-000155'
  tag fix_id: 'F-74381r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
