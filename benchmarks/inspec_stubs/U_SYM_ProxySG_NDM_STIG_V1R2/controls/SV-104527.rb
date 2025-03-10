control 'SV-104527' do
  title 'Symantec ProxySG must implement HTTPS-console to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify only TLS management services are enabled.

1. Log on to Web Management Console.
2. Click Configuration >> Services >> Management Services.
3. Verify "HTTP-Console" is not enabled and that "HTTPS-Console" is enabled.

If Symantec ProxySG does not implement HTTPS-console, this is a finding.'
  desc 'fix', 'Enable TLS management services.

1. Log on to Web Management Console.
2. Click Configuration >> Services >> Management Services.
3. Make sure that "HTTPS-Console" is "Enabled".
4. Uncheck "Enabled" next to that "HTTP-Console".
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94697'
  tag rid: 'SV-104527r1_rule'
  tag stig_id: 'SYMP-NM-000230'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-100815r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
