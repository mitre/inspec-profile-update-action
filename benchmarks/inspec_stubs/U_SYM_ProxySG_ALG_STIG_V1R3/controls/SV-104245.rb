control 'SV-104245' do
  title 'Symantec ProxySG providing user authentication intermediary services must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A nonprivileged account is any account with the authorizations of a nonprivileged user. Privileged roles are organization-defined roles assigned to individuals that allow those individuals to perform certain security-relevant functions that ordinary users are not authorized to perform. Security-relevant roles include key management, account management, network and system administration, database administration, and web administration.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify that only FIPS-compliant HMAC algorithms are in use.

1. Log on to the ProxySG CLI via SSH.
2. Type "show management services".
3. Verify the "Cipher Suite" attribute lists only cipher suites that use FIPS compliant HMAC algorithms.

If any cipher suites are listed that use non-FIPS-compliant HMAC algorithms, this is a finding.'
  desc 'fix', 'Configure the ProxySG to use only FIPS-compliant HMAC algorithms.

1. Log on to the ProxySG SSH CLI.
2. Type "enable" and enter the enable password.
3. Type "configure terminal" and press "Enter".
4. Type "management-services," press "Enter". Type "edit HTTPS-Console" and press "Enter".
5. Type "view" to display the list of configured cipher suites.
6. Type "attribute cipher-suite" followed by a space-delimited list of only cipher suites from step 5 that use FIPS-compliant HMAC algorithms.
7. Press "Enter".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93477r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94291'
  tag rid: 'SV-104245r1_rule'
  tag stig_id: 'SYMP-AG-000380'
  tag gtitle: 'SRG-NET-000147-ALG-000095'
  tag fix_id: 'F-100407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
