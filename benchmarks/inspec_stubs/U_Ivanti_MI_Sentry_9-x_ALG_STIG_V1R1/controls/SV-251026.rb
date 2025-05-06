control 'SV-251026' do
  title 'The Sentry providing mobile device authentication intermediary services must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any account with the authorizations of a non-privileged user. Privileged roles are organization-defined roles assigned to individuals that allow those individuals to perform certain security-relevant functions that ordinary users are not authorized to perform. Security relevant roles include key management, account management, network and system administration, database administration, and web administration.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS). Additional techniques include time-synchronous or challenge-response one-time authenticators.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'The Sentry is configured with TLS by default. The Sentry enables TLS 1.2 by default. To check the status:

1. Log in to MobileIron Sentry.
2. Go to Settings >> Services >> Sentry.
3. For each of the following configurations, follow step 4:
     a. Incoming SSL configuration
     b. Outgoing SSL configuration
     c. UEM SSL configuration
     d. Access SSL configuration
4. In Protocols, verify TLS 1.2 is enabled.

If TLS 1.2 is not enabled for each configuration, this is a finding.

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes subsections on how TLS 1.2 is set as the default protocol:
1. Incoming SSL configuration
2. Outgoing SSL configuration
3. UEM SSL configuration
4. Access SSL configuration

MobileIron Sentry conforms to the NIST SP 800-52 TLS settings by setting TLS 1.2 by default.'
  desc 'fix', 'The Sentry is configured with TLS by default. To configure the Sentry with TLS 1.2:

1. Log in to MobileIron Sentry.
2. Go to Settings >> Services >> Sentry.
3. Select each of the configurations listed below and follow steps 4 and 5:
     a. Incoming SSL configuration
     b. Outgoing SSL configuration
     c. UEM SSL Configuration
     d. Access SSL Configuration
4. In protocols, make TLS 1.2 enabled. 
5. Apply the configuration and click "Save" in the top right corner.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54461r802298_chk'
  tag severity: 'medium'
  tag gid: 'V-251026'
  tag rid: 'SV-251026r802300_rule'
  tag stig_id: 'MOIS-AL-000410'
  tag gtitle: 'SRG-NET-000147-ALG-000095'
  tag fix_id: 'F-54415r802299_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
