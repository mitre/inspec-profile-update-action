control 'SV-222530' do
  title 'The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A privileged account is any information system account with authorizations of a privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review application documentation and interview application administrator to identify what authentication mechanisms are used when accessing the application.

If the application is hosting publicly releasable information that does not require authentication, or if the application users are not eligible for a DoD CAC as per DoD 8520, this requirement is not applicable.

Review to ensure the application is utilizing TLSV1.2 or greater to protect communication and privileged user authentication traffic.

Verify the application utilizes a strong authentication mechanism such as Kerberos, IPSEC, or Secure Shell (SSH).

- Cryptographically sign web services packets.
- Time stamps and cryptographic hashes are used with web services packets.
- Use WS_Security for web services.

Request the most recent vulnerability scan results and configuration settings.

Verify the configuration is set to test for known replay vulnerabilities.

Request code review results (if available) and review for issues that have been identified as potential replay attack vulnerabilities.

Verify identified issues have been remediated.

If the application is not implementing replay-resistant authentication methods applicable to the application architecture, this is a finding.'
  desc 'fix', 'Design and configure the application to utilize replay-resistant mechanisms when authenticating privileged accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24200r504901_chk'
  tag severity: 'medium'
  tag gid: 'V-222530'
  tag rid: 'SV-222530r508029_rule'
  tag stig_id: 'APSC-DV-001620'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-24189r493499_fix'
  tag 'documentable'
  tag legacy: ['SV-84165', 'V-69543']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
