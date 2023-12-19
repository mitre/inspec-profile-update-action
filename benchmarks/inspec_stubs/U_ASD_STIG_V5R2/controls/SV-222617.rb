control 'SV-222617' do
  title 'The application must notify the ISSO and ISSM of failed security verification tests.'
  desc 'If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain.

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Review the application documentation and interview the system administrator to determine if the application performs security function testing.

If the application is not designed or intended to perform security function testing, the requirement is not applicable.

Access the application design documents or have the system administrator provide proof the application is designed to verify the correct operation of security functions.

Review application logs and take note of log entries that indicate security function testing is being performed and verified on startup, restart, or on command by an authorized user.

Review logs to identify if the application has sent notifications to ISSO and ISSM when security verification tests fail.

Review application features and function to identify areas of the management interfaces that specify where failed security verifications tests are to be sent and validate the ISSO and ISSM are configured as recipients.
 
If the application is designed to perform security function testing and does not notify the ISSO and ISSM of failed verification tests, this is a finding.'
  desc 'fix', 'Configure the application to send notices to the ISSO and ISSM indicating the application failed a verification test.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24287r493759_chk'
  tag severity: 'low'
  tag gid: 'V-222617'
  tag rid: 'SV-222617r508029_rule'
  tag stig_id: 'APSC-DV-002780'
  tag gtitle: 'SRG-APP-000275'
  tag fix_id: 'F-24276r493760_fix'
  tag 'documentable'
  tag legacy: ['SV-84909', 'V-70287']
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
