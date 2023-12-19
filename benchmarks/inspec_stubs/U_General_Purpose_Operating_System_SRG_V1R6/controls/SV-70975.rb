control 'SV-70975' do
  title 'The operating system must shut down the information system, restart the information system, and/or notify the system administrator when anomalies in the operation of any security functions are discovered.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.'
  desc 'check', 'Verify the operating system shuts down the information system, restarts the information system, and/or notifies the system administrator when anomalies in the operation of any security functions are discovered. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to shut down the information system, restart the information system, and/or notify the system administrator when anomalies in the operation of the security functions are discovered.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56715'
  tag rid: 'SV-70975r1_rule'
  tag stig_id: 'SRG-OS-000447-GPOS-00201'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-61611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
