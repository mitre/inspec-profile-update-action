control 'SV-206696' do
  title 'The firewall must fail to a secure state upon the failure of the following: system initialization, shutdown, or system abort.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Network elements that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving the information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Verify the firewall stops forwarding traffic or maintains the configured security policies upon the failure of the following: system initialization, shutdown, or system abort.

If the firewall does not stop forwarding traffic or maintain the configured security policies upon the failure of system initialization, shutdown, or system abort, this is a finding.'
  desc 'fix', 'Configure the firewall to stop forwarding traffic or maintain the configured security policies upon the failure of the following actions: system initialization, shutdown, or system abort.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6953r457836_chk'
  tag severity: 'medium'
  tag gid: 'V-206696'
  tag rid: 'SV-206696r604133_rule'
  tag stig_id: 'SRG-NET-000235-FW-000133'
  tag gtitle: 'SRG-NET-000235'
  tag fix_id: 'F-6953r457837_fix'
  tag 'documentable'
  tag legacy: ['SV-94169', 'V-79463']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
