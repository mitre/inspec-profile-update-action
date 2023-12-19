control 'SV-93745' do
  title 'If the BlackBerry Connect service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to enable SSL support for BlackBerry Proxy and use only DoD approved certificates.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS) or SSL. Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Connect service is not enabled on BEMS.

Verify SSL is enabled for the BlackBerry Connect service and a DoD certificate is used as follows:

1. Browse to FQDN of the BEMS Connect server(s) on port 8082.
2. Click on the SSL certificate to verify it has been issued by the DoD CA.
3. Repeat steps 1 and 2 for each BEMS server that has the Connect service added to it.

If SSL is not enabled for BlackBerry Connect and if the SSL certificate is not a DoD CA issued certificate, this is a finding.'
  desc 'fix', 'Configure BlackBerry Connect to enable SSL with a DoD certificate.

1. Submit a CSR request to the DoD CA.
2. Import the DoD certificate to the computer that hosts BEMS.
3. Bind the SSL certificate to the Connect SSL port.
4. Add the new certificate information to the BEMS configuration file.
5. Configure BlackBerry Connect to send requests over SSL.
6. Configure Connect to use SSL with BlackBerry Proxy.'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79039'
  tag rid: 'SV-93745r1_rule'
  tag stig_id: 'BEMS-00-014300'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85789r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
