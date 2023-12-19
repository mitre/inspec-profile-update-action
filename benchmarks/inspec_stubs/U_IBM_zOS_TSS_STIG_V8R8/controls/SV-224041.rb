control 'SV-224041' do
  title 'IBM z/OS system administrator must develop a procedure to shut down the information system, restart the information system, and/or notify the system administrator when anomalies in the operation of any security functions are discovered.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.'
  desc 'check', 'Ask the system administrator for the procedure to shut down the information system, restart the information system, and/or notify the system administrator when anomalies occur.

If a procedure does not exist, this is a finding.

If the procedure does not properly shut down the information system, restart the information system, and/or notify the system administrator when anomalies occur, this is a finding.'
  desc 'fix', 'Develop a procedure to shut down the information system, restart the information system, and/or notify the system administrator when anomalies occur.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25714r516522_chk'
  tag severity: 'medium'
  tag gid: 'V-224041'
  tag rid: 'SV-224041r856129_rule'
  tag stig_id: 'TSS0-OS-000460'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-25702r516523_fix'
  tag 'documentable'
  tag legacy: ['SV-107893', 'V-98789']
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
