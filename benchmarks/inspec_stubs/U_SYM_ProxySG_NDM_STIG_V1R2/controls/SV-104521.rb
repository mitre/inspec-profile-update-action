control 'SV-104521' do
  title 'Symantec ProxySG must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Verify all management certificates are issued by an appropriate certificate authority.

1. Log on to the Web Management Console.
2. Click Services >> Management Services, click on HTTPS-Console and click "Edit".
3. Note the name of the "keyring" assigned.
4. Click Configuration >> SSL >> Keyrings.
5. Select the keyring that was noted above, click "View Certificate".
6. Confirm that the certificate is issued by the appropriate certificate authority.

If Symantec ProxySG does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Assign an appropriately signed certificate to the management interface.

1. Log on to the Web Management Console.
2. Click Configuration >> SSL >> Keyrings.
3. Click "Create", provide a name and bit size, click "OK".
4. Select the newly created keyring, click "Edit".
5. Click "Create" under "Certificate Signing Request" and enter the appropriate information, click "OK", click "Close", click "Apply".
6. Select the newly created keyring, click "Edit".
7. Copy the text in the "Certificate Signing Request" field and submit to your appropriate Certificate Authority.
8. Once the certificate has been issued, paste it into the "Certificate" field, click "Close", click "Apply".
9. Click Services >> Management Services, click on "HTTPS-Console", click "Edit".
10. Change the "Keyring" value to the newly created keyring, click "OK", click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94691'
  tag rid: 'SV-104521r1_rule'
  tag stig_id: 'SYMP-NM-000200'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-100809r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
