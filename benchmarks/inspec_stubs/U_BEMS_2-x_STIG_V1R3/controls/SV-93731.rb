control 'SV-93731' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must be configured to use DoD certificates for SSL.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.'
  desc 'check', 'Verify a DoD SSL certificate has been installed on BEMS as follows:

1. Open the browser.
2. Browse to the BEMS dashboard.
3. Select SSL certificate and view the certificate.
4. Verify the certificate is a DoD certificate (has the DoD CA listed in the certificate).

If the SSL certificate installed on BEMS is not a DoD certificate, this is a finding.'
  desc 'fix', 'Replace the auto-generated BEMS SSL certificate with a DoD certificate as follows:

1. Generate a CSR request and obtain a certificate from the DoD CA.
2. Import the certificate into the BEMS keystore.
3. Update the certificate passwords in BEMS.'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79025'
  tag rid: 'SV-93731r1_rule'
  tag stig_id: 'BEMS-00-013600'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85775r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
