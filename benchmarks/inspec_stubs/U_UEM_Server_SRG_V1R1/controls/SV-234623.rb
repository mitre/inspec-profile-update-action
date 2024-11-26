control 'SV-234623' do
  title 'The UEM server must run a suite of self-tests during initial start-up (power on) to demonstrate correct operation of the server.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing. 

Satisfies:FPT_TST_EXT.1.1'
  desc 'check', 'Verify the UEM server runs a suite of self-tests during initial start-up (power on) to demonstrate correct operation of the server.

If the UEM server does not run a suite of self-tests during initial start-up (power on) to demonstrate correct operation of the server, this is a finding.'
  desc 'fix', 'Configure the UEM server to run a suite of self-tests during initial start-up (power on) to demonstrate correct operation of the server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37808r616004_chk'
  tag severity: 'medium'
  tag gid: 'V-234623'
  tag rid: 'SV-234623r617355_rule'
  tag stig_id: 'SRG-APP-000473-UEM-000348'
  tag gtitle: 'SRG-APP-000473'
  tag fix_id: 'F-37773r615504_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
