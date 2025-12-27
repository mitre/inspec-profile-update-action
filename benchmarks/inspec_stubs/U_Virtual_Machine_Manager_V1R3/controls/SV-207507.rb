control 'SV-207507' do
  title 'The VMM must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the VMM responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by VMMs include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.'
  desc 'check', 'Verify the VMM performs verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7764r365925_chk'
  tag severity: 'medium'
  tag gid: 'V-207507'
  tag rid: 'SV-207507r854681_rule'
  tag stig_id: 'SRG-OS-000446-VMM-001790'
  tag gtitle: 'SRG-OS-000446'
  tag fix_id: 'F-7764r365926_fix'
  tag 'documentable'
  tag legacy: ['SV-71575', 'V-57315']
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
