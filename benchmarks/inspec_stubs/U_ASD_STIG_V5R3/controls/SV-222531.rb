control 'SV-222531' do
  title 'The application must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack is a man-in-the-middle style attack which allows an attacker to repeat or alter a valid data transmission that may enable unauthorized access to the application. Authentication sessions between the authenticating client and the application server validating the user credentials must not be vulnerable to a replay attack.

The protection methods selected to protect against a replay attack will vary according to the application architecture.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any operating system account with authorizations of a non-privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS, WS_Security) and PKI certificates. Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify what authentication mechanisms are used when accessing the application.

If the application is hosting publicly releasable information that does not require authentication, or if the application users are not eligible for a DoD CAC as per DoD 8520, this requirement is not applicable.

Review to ensure the application is utilizing TLSV1.2 or greater to protect communication and non-privileged user authentication traffic.

Verify the application utilizes a strong authentication mechanism such as Kerberos, IPSEC, or Secure Shell (SSH).

- Cryptographically sign web services packets.
- Time stamps and cryptographic hashes are used with web services packets.
- Use WS_Security for web services.

Request the most recent vulnerability scan results and configuration settings.

Verify the configuration is set to test for known replay vulnerabilities.

Request code review results (if available) and review for issues that have been identified as potential replay attack vulnerabilities.

Verify identified issues have been remediated.

If the application is not implementing replay-resistant authentication methods applicable to the application architecture, this is a finding.'
  desc 'fix', 'Design and configure the application to utilize replay-resistant mechanisms when authenticating non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36246r602302_chk'
  tag severity: 'medium'
  tag gid: 'V-222531'
  tag rid: 'SV-222531r879598_rule'
  tag stig_id: 'APSC-DV-001630'
  tag gtitle: 'SRG-APP-000157'
  tag fix_id: 'F-24190r493502_fix'
  tag 'documentable'
  tag legacy: ['SV-84167', 'V-69545']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
