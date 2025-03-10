control 'SV-42593' do
  title 'The DoD Root CA certificates must be installed in the Trusted Root Store.'
  desc 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certificate Authorities (CAs). The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.'
  desc 'check', 'Verify the DoD Root CA certificates are installed as Trusted Root Certification Authorities.

Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".
If there are no entries for "DoD Root CA 2", "DoD Root CA 3", and "DoD Root CA 4", this is a finding.

For each of the DoD Root CA certificates noted above:
Right click on the certificate and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint".

If the value for the "Thumbprint" field is not as noted below, this is a finding.
DoD Root CA 2 - 8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561
DoD Root CA 3 - D73CA91102A2204A36459ED32213B467D7CE97FB
DoD Root CA 4 - B8269F25DBD937ECAFD4C35A9838571723F2D026

The thumbprints referenced apply to unclassified systems; see PKE documentation for other networks.'
  desc 'fix', 'Install the DoD Root CA certificates.
DoD Root CA 2
DoD Root CA 3
DoD Root CA 4

The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-71103r2_chk'
  tag severity: 'medium'
  tag gid: 'V-32272'
  tag rid: 'SV-42593r4_rule'
  tag stig_id: 'WINPK-000001'
  tag gtitle: 'WINPK-000001'
  tag fix_id: 'F-76947r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end
