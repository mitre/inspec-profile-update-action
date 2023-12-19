control 'SV-79713' do
  title 'The DataPower Gateway providing user authentication intermediary services must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any account with the authorizations of a non-privileged user. Privileged roles are organization-defined roles assigned to individuals that allow those individuals to perform certain security-relevant functions that ordinary users are not authorized to perform. Security relevant roles include key management, account management, network and system administration, database administration, and web administration.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS). Additional techniques include time-synchronous or challenge-response one-time authenticators.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'To verify that DataPower requires mutual authentication when establishing TLS connections to remote hosts, click on the Multi-Protocol Gateway or Web Service Proxy icons on the Control Panel (the initial screen).

Click on the configured available service(s) to view its configuration.

For Multi-Protocol Gateway, scroll down to view User Agent Settings >> Verify that the SSL Configuration is set to Client Profile or Proxy Profile >> Click the ellipses (...) button to view the configuration of the Client Profile or Proxy Profile.

For SSL Client Profile, verify that only TLS v1.1 and v1.2 are enabled.

For SSL Client Profile, verify that a validation credential is configured.

For SSL Proxy Profile, click the ellipses (…) button to view the configuration of the Crypto Profile >> Verify that all Options are disabled except TLS version 1.1 and 1.2 >> Verify that a Validation Credential is configured.

To verify that DataPower requires mutual authentication when accepting TLS connections from remote hosts, click on the Multi-Protocol Gateway or Web Service Proxy icons on the Control Panel (the initial screen) >> Click on the configured available service(s) to view its configuration.

For Multi-Protocol Gateway, scroll down to view the Front Side Protocol settings >> Select the current HTTPS Front Side Handler from the dropdown list >> Click “…” to view configuration of the Handler >> Click “...” to view the configuration of the SSL Server Profile or SSL Proxy Profile.

For SSL Server Profile, verify that only TLS v1.1 and v1.2 are enabled.

For SSL Server Profile, verify that a validation credential is configured.

For SSL Proxy Profile, click “…” to view the configuration of the Crypto Profile >> Verify that the Ciphers are only HIGH >> Verify that all Options are disabled except TLS version 1.1 and 1.2 >> Verify that Always Request Client Authentication is set to On >> Verify that a Validation Credential is configured. If they are not, this is a finding.

Use the WebGUI Control panel to select and open a specific service, then open its processing policy. Confirm that a rule with a filter action exists and that the method is "Replay Filter". If they are not, this is a finding.

To confirm interface isolation has been correctly maintained, use the WebGUI at Network >> Interface >> Network Settings. Confirm that Relax interface Isolation is Off.

Confirm Disable interface isolation is Off. If they are not, this is a finding.'
  desc 'fix', 'To define mutual TLS connections when the DataPower device is the requesting client, use the DataPower WebGUI at Objects >> Crypto Configuration.
 
Click SSL Client Profile >> Click Add to create a new one if one does not already exist.

Provide a name >> Deselect all Protocols except TLS version 1.1 and 1.2 >> Deselect Use SNI >> Choose an active Identification Credential from the list. This determines the local keys.

If no ID Creds exist, click “+” to create one. You will need access to the key files you want to use.

Choose an active Validation credentials object from the list.  

If no Val Creds exist, click “+” to create one. You will need access to the server certs you want to validate.

Click Apply >> Click Save Configuration.

Use this new SSL Client Profile when configuring a service, such as a Multi-Protocol Gateway or Web Service Proxy, to connect to other servers. If the remote server will not agree to TLS v1.2 or v1.1 and does not provide a certificate that is validated, the connection will not be established. 

To define mutual TLS connections when the DataPower device is the server, use the DataPower WebGUI at Objects >> Crypto Configuration.
 
Click SSL Server Profile >> Click Add to create a new one if one does not already exist.

Provide a name >> Deselect all Protocols except TLS version 1.1 and 1.2 >> Choose an active Identification Credential from the list. This determines the local keys.

If no ID Creds exist, click “+” to create one. You will need access to the key files you want to use.

Set Request client authentication to On >> Choose an active Validation credentials object from the list.

If no Val Creds exist, click “+” to create one. You will need access to the server certs you want to validate.

Click Apply >> Click Save Configuration.

Use this new SSL Server Profile when configuring an HTTPS Front Side Handler, which is in turn used by a service, such as a Multi-Protocol Gateway or Web Service Proxy to accept incoming requests. If the remote client will not agree to TLS v1.2 or v1.1 and does not provide a certificate that is validated, the connection will not be established. 

Replay filter(s). Use the WebGUI to define a replay filter processing action. From the DataPower WebGUI, click on then add a service type (e.g., Web Service Proxy). Add a policy (in this case, a Multi-Protocol gateway Policy). Create a processing rule. Add a Filter action. Specify "Replay Filter" as the method.

Network interface isolation: By default, the DataPower Gateway provides interface isolation: the appliance refuses to accept a packet on an interface other than the one bound to the destination address of the packet. Use the WebGUI at Network >> Interface >> Network Settings to configure a network interface.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65223'
  tag rid: 'SV-79713r1_rule'
  tag stig_id: 'WSDP-AG-000041'
  tag gtitle: 'SRG-NET-000147-ALG-000095'
  tag fix_id: 'F-71163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
