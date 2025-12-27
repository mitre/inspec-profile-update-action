control 'SV-254114' do
  title 'Nutanix AOS must use DoD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.

'
  desc 'check', 'Confirm Nutanix AOS is configured with a trusted DoD root CA signed certificate.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the SSL Certificate section.
4. Ensure the approved CA signed certificate is installed.

If the certificate used is not from an approved DoD-approved CA, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to use a trusted DoD root CA signed certificate.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the SSL Certificate section.
4. Click "Relace Certificate".
5. Select "Import Key and Certificate".
6. Select the Private Key Type and upload the Private key; Public Certificate, and the CA Certificate or chain.
7. Select "Import Files".'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57599r846428_chk'
  tag severity: 'high'
  tag gid: 'V-254114'
  tag rid: 'SV-254114r846430_rule'
  tag stig_id: 'NUTX-AP-000430'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-57550r846429_fix'
  tag satisfies: ['SRG-APP-000514-AS-000137', 'SRG-APP-000427-AS-000264']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002470']
  tag nist: ['SC-13 b', 'SC-23 (5)']
end
