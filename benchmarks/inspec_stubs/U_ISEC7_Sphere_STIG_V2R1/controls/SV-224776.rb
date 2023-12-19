control 'SV-224776' do
  title 'If cipher suites using pre-shared keys are used for device authentication, the ISEC7 EMM Suite must have a minimum security strength of 112 bits or higher, must only be used in networks where both the client and server are Government systems, must prohibit client negotiation to TLS 1.1, TLS 1.0, SSL 2.0, or SSL 3.0 and must prohibit or restrict the use of protocols that transmit unencrypted authentication information or use flawed cryptographic algorithm for transmission.'
  desc 'Pre-shared keys are symmetric keys that are already in place prior to the initiation of a Transport Layer Security (TLS) session (e.g., as the result of a manual distribution). In general, pre-shared keys should not be used. However, the use of pre-shared keys may be appropriate for some closed environments that have stung key management best practices. 

Pre-shared keys may be appropriate for constrained environments with limited processing, memory, or power. If pre-shared keys are appropriate and supported, the following additional guidelines must be followed. Consult 800-52 for recommended pre-shared key cipher suites for pre-shared keys. Pre-shared keys must be distributed in a secure manner, such as a secure manual distribution or using a key establishment certificate. These cipher suites employ a pre-shared key for device authentication (for both the server and the client) and may also use RSA or ephemeral Diffie-Hellman (DHE) algorithms for key establishment. 

Because these cipher suites require pre-shared keys, these suites are not generally applicable to classic secure website applications and are not expected to be widely supported in TLS clients or TLS servers. NIST suggests that these suites be considered in particular for infrastructure applications, particularly if frequent authentication of the network entities is required. These cipher suites may be used with TLS versions 1.1 or 1.2. Note that cipher suites using GCM, SHA-256, or SHA-384 are only available in TLS 1.2.

Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation, either on DoD-only or on public-facing servers.

If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.

'
  desc 'check', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Verify that sslProtocol is set to TLS1.2.

If the sslProtocol is not set to TLS1.2, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Verify that sslProtocol is set to TLS1.2.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26467r461584_chk'
  tag severity: 'medium'
  tag gid: 'V-224776'
  tag rid: 'SV-224776r505933_rule'
  tag stig_id: 'ISEC-06-002620'
  tag gtitle: 'SRG-APP-000585'
  tag fix_id: 'F-26455r461585_fix'
  tag satisfies: ['SRG-APP-000585', 'SRG-APP-000590', 'SRG-APP-000560', 'SRG-APP-000645']
  tag 'documentable'
  tag legacy: ['SV-106515', 'V-97411']
  tag cci: ['CCI-000382', 'CCI-001967', 'CCI-001453']
  tag nist: ['CM-7 b', 'IA-3 (1)', 'AC-17 (2)']
end
