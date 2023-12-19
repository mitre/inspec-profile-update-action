control 'SV-32473' do
  title 'A private web-site must utilize certificates from a trusted DoD CA.'
  desc 'The use of a DoD PKI certificate ensures clients the private web site they are connecting to is legitimate, and is an essential part of the DoD defense-in-depth strategy.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click Bindings in the Action Pane.
4. Click the HTTPS type from the box.
5. Click Edit.
6. Click View, review and verify the certificate path. If the list of CAs in the trust hierarchy does not lead to the DoD PKI Root CA, DoD-approved external certificate authority (ECA), or DoD-approved external partner, this is a finding.  If HTTPS is not an available type under site bindings, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Server name.
3. Double-Click Server Certificates.
4. Click Import under the Actions Pane.
5. Browse to the DoD certificate location, select it, and click OK.
6. Remove any non-DoD certificates if present.
7. Click on the site needing the certificate.
8. Select Bindings under the Actions Pane.
9. Click on the binding needing a certificate and select edit, or add a site binding for HTTPS and execute step 10.
10. Assign the certificate to the web site by choosing it under the SSL Certificate drop down and clicking OK.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32790r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13620'
  tag rid: 'SV-32473r2_rule'
  tag stig_id: 'WG355 IIS7'
  tag gtitle: 'WG355'
  tag fix_id: 'F-29071r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Web Administrator']
end
