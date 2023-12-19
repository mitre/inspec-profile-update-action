control 'SV-203757' do
  title 'The operating system must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify the operating system performs verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3882r375392_chk'
  tag severity: 'medium'
  tag gid: 'V-203757'
  tag rid: 'SV-203757r380296_rule'
  tag stig_id: 'SRG-OS-000446-GPOS-00200'
  tag gtitle: 'SRG-OS-000446'
  tag fix_id: 'F-3882r375393_fix'
  tag 'documentable'
  tag legacy: ['V-56717', 'SV-70977']
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
