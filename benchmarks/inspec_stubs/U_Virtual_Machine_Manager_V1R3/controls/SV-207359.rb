control 'SV-207359' do
  title 'The VMM must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'It is critical that when the VMM is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the VMM must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner. 

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the VMM must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify the VMM shuts down by default upon audit failure (unless availability is an overriding concern). If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to shut down by default upon audit failure (unless availability is an overriding concern).'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7616r365487_chk'
  tag severity: 'medium'
  tag gid: 'V-207359'
  tag rid: 'SV-207359r378637_rule'
  tag stig_id: 'SRG-OS-000047-VMM-000220'
  tag gtitle: 'SRG-OS-000047'
  tag fix_id: 'F-7616r365488_fix'
  tag 'documentable'
  tag legacy: ['SV-71155', 'V-56895']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
