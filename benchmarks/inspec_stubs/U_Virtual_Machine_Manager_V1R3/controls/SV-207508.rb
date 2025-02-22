control 'SV-207508' do
  title 'The VMM must shut down, restart, and/or notify the system administrator when anomalies in the operation of any security functions are discovered.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the VMM responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by VMMs include messages to local computer consoles, hardware indications, such as lights, and/or notifying SAs via email or monitoring system traps.

This capability must take into account operational requirements for availability when selecting an appropriate response. The organization may choose to shut down or restart the VMM or send notifications to SAs upon security function anomaly detection.'
  desc 'check', 'Verify the VMM shuts down, restarts, and/or notifies the system administrator when anomalies in the operation of any security functions are discovered.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to shut down, restart, and/or notify the system administrator when anomalies in the operation of any security functions are discovered.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7765r365928_chk'
  tag severity: 'medium'
  tag gid: 'V-207508'
  tag rid: 'SV-207508r854682_rule'
  tag stig_id: 'SRG-OS-000447-VMM-001800'
  tag gtitle: 'SRG-OS-000447'
  tag fix_id: 'F-7765r365929_fix'
  tag 'documentable'
  tag legacy: ['SV-71577', 'V-57317']
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
