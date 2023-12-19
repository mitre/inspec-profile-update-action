control 'SV-86147' do
  title 'The CA API Gateway must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'It is critical that when the network device is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the network device must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.
(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the network device must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify the "/etc/audit/auditd.conf" file contains the lines: 

disk_full_action = HALT
disk_error_action = HALT

If "/etc/audit/auditd.conf" does not contain these lines, this is a finding.'
  desc 'fix', 'Configure the "auditd" configuration file "/etc/audit/auditd.conf" by adding these lines: 

disk_full_action = HALT
disk_error_action = HALT'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71523'
  tag rid: 'SV-86147r1_rule'
  tag stig_id: 'CAGW-DM-000120'
  tag gtitle: 'SRG-APP-000109-NDM-000233'
  tag fix_id: 'F-77843r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
