control 'SV-251560' do
  title 'Firefox must have the DoD root certificates installed.'
  desc 'The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD Certificate Authority (CA).'
  desc 'check', 'Type "about:preferences#privacy" in the browser window. 

Scroll down to the bottom and select "View Certificates...".

In the Certificate Manager window, select the "Authorities" tab.

Scroll through the Certificate Name list to the U.S. Government heading. Look for the entries for DoD Root CA 2, DoD Root CA 3, DoD Root CA 4, and DoD Root CA 5.

If there are entries for DoD Root CA 2, DoD Root CA 3, DoD Root CA 4, and DoD Root CA 5, select them individually.

Click the "View" button.

Verify the publishing organization is "US Government".

If there are no entries for the DoD Root CA 2, DoD Root CA 3, DoD Root CA 4, and DoD Root CA 5, this is a finding. If other AO-approved certificates are used, this is not a finding.

Note: In a Windows environment, use of policy setting "security.enterprise_roots.enabled=true" will point Firefox to the Windows Trusted Root Certification Authority Store. This is not a finding. It may also be set via the policy Certificates >> ImportEnterpriseRoots, which can be verified via "about:policies".'
  desc 'fix', 'Install the DoD root certificates. Other AO-approved certificates may also be used.

On Windows, import certificates from the operating system by using Certificates >> Import Enterprise Roots (Certificates) via policy or Group Policy Object (GPO).'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54995r862959_chk'
  tag severity: 'medium'
  tag gid: 'V-251560'
  tag rid: 'SV-251560r862961_rule'
  tag stig_id: 'FFOX-00-000016'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-54949r862960_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
