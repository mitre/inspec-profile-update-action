control 'SV-254724' do
  title 'If the BlackBerry Connect service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to enable SSL support for BlackBerry Proxy and use only DOD approved certificates.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS) or SSL. Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Connect service is not enabled on BEMS.

Verify SSL is enabled for the BlackBerry Connect service and a DOD certificate is used as follows:

1. Browse to FQDN of the BEMS Connect server(s) on port 8082.
2. Click on the SSL certificate to verify it has been issued by the DOD CA.
3. Repeat steps 1 and 2 for each BEMS server that has the Connect service added to it.

If SSL is not enabled for BlackBerry Connect and if the SSL certificate is not a DOD CA issued certificate, this is a finding.'
  desc 'fix', 'Configure BlackBerry Connect to enable SSL with a DOD certificate.

1. Submit a CSR request to the DOD CA.
2. In BEMS Select "SSL Certificate".
3. Select "Choose File" and select the new SSL Certificate and type the "Password".
4. Configure BlackBerry Connect to send the request over SSL (see page 20 of the BEMS Configuring the BlackBerry Connect Service document).
5. Configure Connect to use SSL with BlackBerry Proxy (see page 20 of the BEMS Configuring the BlackBerry Connect Service document).'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58335r861895_chk'
  tag severity: 'medium'
  tag gid: 'V-254724'
  tag rid: 'SV-254724r879887_rule'
  tag stig_id: 'BEMS-03-014300'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58281r861896_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
