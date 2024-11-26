control 'SV-218767' do
  title 'The IIS 10.0 website must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'The use of a DoD PKI certificate ensures clients the private website they are connecting to is legitimate, and is an essential part of the DoD defense-in-depth strategy.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Click "Bindings" in the "Action" Pane.

Click the "HTTPS type" from the box.

Click "Edit".

Click "View" and then review and verify the certificate path.

If the list of CAs in the trust hierarchy does not lead to the DoD PKI Root CA, DoD-approved external certificate authority (ECA), or DoD-approved external partner, this is a finding.

If HTTPS is not an available type under site bindings, this is a finding.

If HTTPS is not an available type under site bindings, and the Web Server ONLY communicates directly with a load balancer/proxy server with IP address and Domain Restrictions in place, this is not a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the Server name.

Double-click "Server Certificates".

Click "Import" under the "Actions" pane.

Browse to the DoD certificate location, select it, and click "OK".

Remove any non-DoD certificates if present.

Click on the site needing the certificate.

Select "Bindings" under the "Actions" pane.

Click on the binding needing a certificate and select "Edit", or add a site binding for HTTPS.

Assign the certificate to the website by choosing it under the "SSL Certificate" drop-down and clicking "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20240r311199_chk'
  tag severity: 'medium'
  tag gid: 'V-218767'
  tag rid: 'SV-218767r879798_rule'
  tag stig_id: 'IIST-SI-000241'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-20238r311200_fix'
  tag 'documentable'
  tag legacy: ['SV-109359', 'V-100255']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
