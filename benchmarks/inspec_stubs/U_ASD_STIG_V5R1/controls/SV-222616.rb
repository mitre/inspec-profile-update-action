control 'SV-222616' do
  title 'The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed.

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Review the application documentation and interview the system administrator to determine if the application performs security function testing.

If the application is not designed or intended to perform security function testing, the requirement is not applicable.

Access the application design documents or have the system administrator provide proof if the application is designed to verify the correct operation of security functions.

Review application logs and take note of log entries that indicate security function testing is being performed and verified on startup, restart, or on command by an authorized user.

If the application is designed to perform security function testing and does not verify the correct operation of security functions on startup, restart, or upon command by a privileged user, this is a finding.'
  desc 'fix', 'Design the application to verify the correct operation of security functions on command and on application startup and restart.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24286r493756_chk'
  tag severity: 'medium'
  tag gid: 'V-222616'
  tag rid: 'SV-222616r508029_rule'
  tag stig_id: 'APSC-DV-002770'
  tag gtitle: 'SRG-APP-000473'
  tag fix_id: 'F-24275r493757_fix'
  tag 'documentable'
  tag legacy: ['V-70285', 'SV-84907']
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
