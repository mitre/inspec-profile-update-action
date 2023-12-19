control 'SV-222543' do
  title 'The application must transmit only cryptographically-protected passwords.'
  desc 'Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Applications can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Identify when the application transmits passwords. This will most likely be when the user authenticates to the application or when the application authenticates to another resource.

Access the application management interface with a test account and access the functionality that requires a password be provided. If the interface is via a web browser, verify the web browser has gone secure prior to entering any password or authentication information.

This can be done by viewing the browser and observing a “lock” icon displayed somewhere in the browser as well as an https:// to indicate an SSL connection. Most browsers display this in the upper left hand corner.

If the application is transmitting the password rather than the user, obtain design documentation from the application admin that provides the details on how they are protecting the password during transmission. This will usually be via a TLS/SSL tunneled connection or VPN.

If the passwords are not encrypted when being transmitted, this is a finding.'
  desc 'fix', 'Configure the application to encrypt passwords when they are being transmitted.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24213r493537_chk'
  tag severity: 'high'
  tag gid: 'V-222543'
  tag rid: 'SV-222543r879609_rule'
  tag stig_id: 'APSC-DV-001750'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-24202r493538_fix'
  tag 'documentable'
  tag legacy: ['V-69569', 'SV-84191']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
