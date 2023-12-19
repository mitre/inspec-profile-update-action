control 'SV-77443' do
  title 'Riverbed Optimization System (RiOS) must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify that RiOS is configured to implement replay resistant authentication mechanisms for network access to privileged accounts.

Navigate to the device CLI
Type: enable
Type: show config full
Type: Spacebar to tab through the configuration
Verify that the following commands are contained in the configuration
"no web http enable"
"web https enable"
"no web ssl protocol sslv3"
"no web ssl protocol tlsv1"
"web ssl protocol tlsv1.1"
"web ssl protocol tlsv1.2"

If all of the above configurations are not defined as listed, this is a finding.'
  desc 'fix', 'Configure RiOS to implement replay resistant authentication mechanisms for network access to privileged accounts.

Navigate to the device CLI
Type: enable
Type: conf t
Type: no web http enable
Type: web https enable
Type: no web ssl protocol sslv3
Type: no web ssl protocol tlsv1
Type: web ssl protocol tlsv1.1
Type: web ssl protocol tlsv1.2
Type: write memory
Type: exit
Type: exit'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63705r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62953'
  tag rid: 'SV-77443r1_rule'
  tag stig_id: 'RICX-DM-000106'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-68871r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
