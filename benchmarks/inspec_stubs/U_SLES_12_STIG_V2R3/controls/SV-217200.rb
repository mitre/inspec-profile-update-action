control 'SV-217200' do
  title 'The audit system must take appropriate action when the network cannot be used to off-load audit records.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify what action the audit system takes if it cannot off-load audit records to a different system or storage media from the SUSE operating system being audited.

Check the action that the audit system takes in the event of a network failure with the following command:

# sudo grep -i "network_failure_action" /etc/audisp/audisp-remote.conf

network_failure_action = syslog

If the "network_failure_action" option is not set to "syslog", "single", or "halt" or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to take the appropriate action if it cannot off-load audit records to a different system or storage media from the system being audited due to a network failure.

Uncomment the "network_failure_action" option in "/etc/audisp/audisp-remote.conf" and set it to "syslog", "single", or "halt". See the example below:

network_failure_action = syslog'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18428r369756_chk'
  tag severity: 'medium'
  tag gid: 'V-217200'
  tag rid: 'SV-217200r603262_rule'
  tag stig_id: 'SLES-12-020100'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-18426r369757_fix'
  tag 'documentable'
  tag legacy: ['SV-92003', 'V-77307']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
