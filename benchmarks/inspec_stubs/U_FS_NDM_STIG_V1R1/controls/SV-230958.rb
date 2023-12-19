control 'SV-230958' do
  title 'Forescout must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Determine if Forescout obtains public key certificates from an appropriate certificate policy through an approved service provider.

To review the Web server certificate presented for captive portal/authentication:

1. Open a command line SSH to Forescout appliance or Enterprise Manager.
2. Run the following command:
>fstool cert test
3. Verify all Web server certificate(s) are printed and reviewable.
4. Verify the signing authority is from an approved certificate authority.

If the network device does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Generate a certificate signing request by completing the following procedures: 

1. Navigate to Tools >> Options >> Certificates >> System Certificates. 
2. On the right of the screen click “Generate CSR”.
3. Complete the following fields (bolded fields are necessary for the Common Criteria evaluation and underlined fields have the required selection made): 
- Common Name – <system hostname> 
- Organization – <organizational name> 
- Organizational Unit – <unit name> 
- Locality – <locality name> 
- State – <state name>
- Country Code – <country code> 
- Email Address - <email address>
- Key Length – <select an approved key length from the drop down list>
- Signature Algorithm – <select an approved algorithm from the drop down list>
- Key Usages – < Checking all items that apply Client Authentication, Server Authentication and Email Signing>
- Validity – <years> 
4. Click “Next”.
5. When the CSR is generated, scroll down to ensure the public key and common name are present.
6. Click "Scope option – ALL" and then click "Next".
7. Enter a name for system certificate.
8. Check “Enable presenting this certificate”.
9. Click "Finish".
10. Click "Apply", and then click "Yes" to save the changes.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33888r603713_chk'
  tag severity: 'medium'
  tag gid: 'V-230958'
  tag rid: 'SV-230958r616552_rule'
  tag stig_id: 'FORE-NM-000320'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-33861r616551_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
