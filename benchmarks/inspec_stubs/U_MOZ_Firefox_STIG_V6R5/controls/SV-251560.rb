control 'SV-251560' do
  title 'Firefox must have the DOD root certificates installed.'
  desc 'The DOD root certificates will ensure that the trust chain is established for server certificates issued from the DOD Certificate Authority (CA).'
  desc 'check', 'Type "about:preferences#privacy" in the browser window. 

Scroll down to the bottom and select "View Certificates...".

In the Certificate Manager window, select the "Authorities" tab.

Scroll through the Certificate Name list to the U.S. Government heading. Look for the entries for DOD Root CA 2, DOD Root CA 3, DOD Root CA 4, and DOD Root CA 5.

If there are entries for DOD Root CA 2, DOD Root CA 3, DOD Root CA 4, and DOD Root CA 5, select them individually.

Click the "View" button.

Verify the publishing organization is "US Government".

If there are no entries for the appropriate DOD root certificates, this is a finding. If other AO-approved certificates are used, this is not a finding. If SIPRNet-specific certificates are used, this is not a finding.

Note: In a Windows environment, use of policy setting "security.enterprise_roots.enabled=true" will point Firefox to the Windows Trusted Root Certification Authority Store. This is not a finding. It may also be set via the policy Certificates >> ImportEnterpriseRoots, which can be verified via "about:policies".'
  desc 'fix', 'Install the DOD root certificates. Other AO-approved certificates may also be used. Certificates designed for SIPRNet may be used as appropriate.

On Windows, import certificates from the operating system by using Certificates >> Import Enterprise Roots (Certificates) via policy or Group Policy Object (GPO).'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54995r918131_chk'
  tag severity: 'medium'
  tag gid: 'V-251560'
  tag rid: 'SV-251560r918133_rule'
  tag stig_id: 'FFOX-00-000016'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-54949r918132_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
