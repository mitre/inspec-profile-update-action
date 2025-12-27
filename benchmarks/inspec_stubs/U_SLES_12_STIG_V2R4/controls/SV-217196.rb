control 'SV-217196' do
  title 'The SUSE operating system audit system must take appropriate action when the audit storage volume is full.'
  desc 'It is critical that when the SUSE operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

1) If the failure was caused by the lack of audit record storage capacity, the SUSE operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the SUSE operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify the SUSE operating system takes the appropriate action when the audit storage volume is full. 

Check that the SUSE operating system takes the appropriate action when the audit storage volume is full with the following command:

# sudo grep disk_full_action /etc/audit/auditd.conf

disk_full_action = SYSLOG

If the value of the "disk_full_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to shut down by default upon audit failure (unless availability is an overriding concern).

Add or update the following line (depending on configuration "disk_full_action" can be set to "SYSLOG", "SINGLE", or "HALT" depending on configuration) in "/etc/audit/auditd.conf" file:

disk_full_action = HALT'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18424r369744_chk'
  tag severity: 'medium'
  tag gid: 'V-217196'
  tag rid: 'SV-217196r603262_rule'
  tag stig_id: 'SLES-12-020060'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-18422r369745_fix'
  tag 'documentable'
  tag legacy: ['V-77299', 'SV-91995']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
