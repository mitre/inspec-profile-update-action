control 'SV-258611' do
  title 'The ICS must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved and shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Device Certificates.

1. Verify there is a device certificate that is signed by a valid DOD CA.
2. Verify the certificate is used by all interfaces on the ICS.

If the ICS does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Device Certificates.
1. Click "New CSR".
2. Add a Common Name in FQDN format.
3. Add a Country code of US.
4. Under key type, if using RSA, select "RSA". If using ECC, select "ECC".
5. Under the key length, if using RSA, select at least "2048". If using ECC, select "P-384".
6. Type in "Random Data" in the text field.
7. Click "Create CSR".
8. Copy the Base 64/PEM encoded certificate request that is shown on the screen and paste it to a text file. Ensure the file has the file suffix of .csr.
9. Go through the local RA process for DOD Web Server certificate requests. Ensure that SANs are added to the certificate by the issuing CA to include the hostname, cluster names, and all FQDNs.
10. Once the certificate is provided by the CA, go to System >> Configuration >> Certificates >> Device Certificates.
11. Click "Browse" and select the certificate file issued by the CA, then click "Import".
12. Click "Save Changes".
13. Click on the imported certificate.
14. On the "Internal Port", click "add" for the cluster internal VIP and <Internal Port>.
15. On the "External Port", click "add" for the cluster external VIP and <External Port>.
16. Check the box for "Management Port".
17. Under "Certificate Status Checking", click the box for "Use CRLs".
18. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62351r930519_chk'
  tag severity: 'medium'
  tag gid: 'V-258611'
  tag rid: 'SV-258611r930521_rule'
  tag stig_id: 'IVCS-NM-000370'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-62260r930520_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
