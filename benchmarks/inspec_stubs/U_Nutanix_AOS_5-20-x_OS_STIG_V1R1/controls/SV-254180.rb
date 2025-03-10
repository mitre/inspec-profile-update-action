control 'SV-254180' do
  title 'Nutanix AOS must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows:

1) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Confirm the audit configuration regarding how auditing processing failures are handled in Nutanix AOS.

$ sudo auditctl -s | grep -i "fail"
If the output is not failure 1, this is a finding.'
  desc 'fix', 'Configure the audit alert setting by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57665r846626_chk'
  tag severity: 'medium'
  tag gid: 'V-254180'
  tag rid: 'SV-254180r846628_rule'
  tag stig_id: 'NUTX-OS-000780'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-57616r846627_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
