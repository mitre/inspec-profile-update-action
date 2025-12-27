control 'SV-254717' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must be configured to use DOD certificates for SSL.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.'
  desc 'check', 'Verify a DOD SSL certificate has been installed on BEMS as follows:

1. Open the browser.
2. Browse to the BEMS dashboard.
3. Select SSL certificate and view the certificate.
4. Verify the certificate is a DOD certificate (has the DOD CA listed in the certificate).

If the SSL certificate installed on BEMS is not a DOD certificate, this is a finding.'
  desc 'fix', 'Replace the auto-generated BEMS SSL certificate with a DOD certificate as follows:

1. Generate a CSR request and obtain a certificate from the DOD CA.
2. Import the certificate into the BEMS keystore.
3. Update the certificate passwords in BEMS.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58328r861874_chk'
  tag severity: 'medium'
  tag gid: 'V-254717'
  tag rid: 'SV-254717r879887_rule'
  tag stig_id: 'BEMS-03-013600'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58274r861875_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
