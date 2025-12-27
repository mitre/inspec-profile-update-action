control 'SV-246945' do
  title 'ONTAP must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Use "security login show -authentication-method cert" to see user IDs created with public key certificates from a certificate authority.

If ONTAP cannot obtain its public key certificates from an appropriate certificate policy, this is a finding.'
  desc 'fix', 'Configure ONTAP to use public key certificates for authentication with "security certificate install -type client-ca -vserver <vserver_name>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50377r769165_chk'
  tag severity: 'medium'
  tag gid: 'V-246945'
  tag rid: 'SV-246945r769167_rule'
  tag stig_id: 'NAOT-CM-000008'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-50331r769166_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
