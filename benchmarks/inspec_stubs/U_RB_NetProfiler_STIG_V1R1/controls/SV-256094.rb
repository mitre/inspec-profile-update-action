control 'SV-256094' do
  title 'The Riverbed NetProfiler must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this certification authority will suffice.'
  desc 'check', 'Go to Configuration >> Appliance Security >> Encryption Key Management. 

Under the "Local Credentials" tab, look for the "Apache SSL certificate". 

Under the "Action" column, click the drop-down menu and select "View Certificate". 

Verify the Privacy Enhanced Mail (PEM) format for the certificate and key match the certification authority-provided certificate and the certificate is signed by a DOD-approved certificate authority. 

If this is not true, this is a finding.'
  desc 'fix', 'Go to Configuration >> Appliance Security >> Encryption Key Management. 

Under the "Local Credentials" tab, look for the "Apache SSL certificate". 

Under the "Action" column, click the drop-down menu and select "Change Key/Cert". 

Paste the private key and certificate in PEM format and click "Save". 

Restart the web browser to avoid connection errors.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59768r882788_chk'
  tag severity: 'medium'
  tag gid: 'V-256094'
  tag rid: 'SV-256094r882790_rule'
  tag stig_id: 'RINP-DM-000061'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-59711r882789_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
