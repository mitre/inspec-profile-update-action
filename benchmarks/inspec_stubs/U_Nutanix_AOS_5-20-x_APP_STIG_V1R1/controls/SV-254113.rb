control 'SV-254113' do
  title 'Nutanix AOS must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', %q(Confirm Nutanix AOS is that OCSP checking is enabled.

$ ncli authconfig get-client-authentication-config
 'Auth Config Status        : true'

If "Auth config status" is not set to "true", this is a finding.)
  desc 'fix', 'Configure Nutanix AOS to use OCSP for certificate revocation.

Set the OCSP responder URL.
$ ncli authconfig set-certificate-revocation set-ocsp-responder=<ocsp url><ocsp url>'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57598r846425_chk'
  tag severity: 'high'
  tag gid: 'V-254113'
  tag rid: 'SV-254113r846427_rule'
  tag stig_id: 'NUTX-AP-000360'
  tag gtitle: 'SRG-APP-000175-AS-000124'
  tag fix_id: 'F-57549r846426_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
