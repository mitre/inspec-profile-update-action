control 'SV-234198' do
  title 'The FortiGate device must use DoD-approved Certificate Authorities (CAs) for public key certificates.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this CA will suffice.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Certificates.
3. Verify CAs are approved providers.

If the public key certificates are not from an approved service provider, this is a finding.'
  desc 'fix', '1. Obtain CA certificate from a DoD-approved provider.
2. Log in to the FortiGate GUI with Super-Admin privilege.
3. Click System.
4. Click Certificates.
5. Click Import in the toolbar.
6. Click CA Certificate.
7. On the Import CA Certificate page, select Type File.
8. Locate the certificate file and upload the certificate file.
9. Click OK to import the certificate.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37383r611781_chk'
  tag severity: 'medium'
  tag gid: 'V-234198'
  tag rid: 'SV-234198r879887_rule'
  tag stig_id: 'FGFW-ND-000195'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-37348r611782_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
