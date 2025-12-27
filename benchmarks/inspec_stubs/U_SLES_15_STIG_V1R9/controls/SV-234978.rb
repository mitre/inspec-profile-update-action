control 'SV-234978' do
  title 'The SUSE operating system must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify what action the audit system takes if it cannot off-load audit records to a different system or storage media from the SUSE operating system being audited.

Check the action that the audit system takes in the event of a network failure with the following command:

> sudo grep -i "network_failure_action" /etc/audisp/audisp-remote.conf

network_failure_action = syslog

If the "network_failure_action" option is not set to "syslog", "single", or "halt" or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to take the appropriate action if it cannot off-load audit records to a different system or storage media from the system being audited due to a network failure.

Uncomment the "network_failure_action" option in "/etc/audisp/audisp-remote.conf" and set it to "syslog", "single", or "halt". See the example below:

network_failure_action = syslog'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38166r619203_chk'
  tag severity: 'medium'
  tag gid: 'V-234978'
  tag rid: 'SV-234978r854270_rule'
  tag stig_id: 'SLES-15-030790'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-38129r619204_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
