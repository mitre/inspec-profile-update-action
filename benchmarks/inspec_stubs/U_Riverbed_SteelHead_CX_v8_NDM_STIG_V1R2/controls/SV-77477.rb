control 'SV-77477' do
  title 'Riverbed Optimization System (RiOS) must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Verify that RiOS is configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.

Navigate to the device Management Console
Navigate to Configure >> Optimization >> Certificate Authorities
Verify that DoD Root Certificates are listed on this page

If no DoD Root CA Certificates are listed on this page, this is a finding.'
  desc 'fix', 'Configure RiOS to use public key certificates from an appropriate certificate policy through an approved service provider.

Navigate to the device Management Console
Navigate to Configure >> Optimization >> Certificate Authorities
Click "Add a New Certificate Authority"
Select "Local File" and "Browse"
Navigate to your local DoD CA Root Certificates and select a certificate
Click "Add"
Repeat Click "Add a New Certificate Authority" down to Click "Add" for each DoD Root Certificate

Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62987'
  tag rid: 'SV-77477r1_rule'
  tag stig_id: 'RICX-DM-000138'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-68905r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
