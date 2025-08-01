control 'SV-102395' do
  title 'The SEL-2740S must be adopted by OTSDN Controller(s) and obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Ensure the SEL-2740S X.509 certificate is properly configured on the SEL-2740S by checking the "Certificates" page on the OTSDN Controller.  

If the SEL-2740S public keys were not provided by an approved certificate policy or authority, this is a finding.'
  desc 'fix', 'Import a PEM or PFX X.509 Certificate from an approved service provider into the flow controller as the Root CA certificate so the flow controller can use it to generate and commission the SEL-2740S with an accepted chain of trust.  To do this log into the flow controller with security administrator privileges and navigate to the Administration page and then to the X.509 page.  Select Import and use the certificate type CA Cert.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91603r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92307'
  tag rid: 'SV-102395r1_rule'
  tag stig_id: 'SELS-ND-001410'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-98545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
