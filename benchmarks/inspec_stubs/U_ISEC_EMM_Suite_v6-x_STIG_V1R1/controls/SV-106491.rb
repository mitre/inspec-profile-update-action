control 'SV-106491' do
  title 'The ISEC7 EMM Suite must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications and is not applicable to virtual private network (VPN) devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DoD-only or on public-facing servers.'
  desc 'check', 'Login to the EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Verify sslProtocol is set to TLSv1.2.

If the sslProtocol is not set to TLSv1.2, this is a finding.'
  desc 'fix', 'Login to the EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Using the dropdown menu for sslProtocol, select TLSv1.2.
Click Update.
Restart the ISEC7 EMM Suite Web service.'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96223r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97387'
  tag rid: 'SV-106491r1_rule'
  tag stig_id: 'ISEC-06-000060'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-103067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
