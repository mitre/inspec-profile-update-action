control 'SV-82989' do
  title 'The Mainframe Product must either shut down, restart, and/or notify the appropriate personnel when anomalies in the operation of the security functions as defined in site security plan are discovered.'
  desc 'If anomalies are not acted on, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Examine installation and configuration setting

If the Mainframe Product is not configured to shut down; and/or restart and notify system programmer and operation staff when anomalies in the operation of security functions as defined by site security plan are discovered, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to shut down; and/or restart and notify system programmer and operation staff when anomalies in the operation of the security functions as defined in site security plan are discovered.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69031r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68499'
  tag rid: 'SV-82989r1_rule'
  tag stig_id: 'SRG-APP-000474-MFP-000373'
  tag gtitle: 'SRG-APP-000474-MFP-000373'
  tag fix_id: 'F-74615r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
