control 'SV-223179' do
  title 'The DOD Root Certificate is not installed.'
  desc 'The DOD root certificate will ensure that the trust chain is established for server certificate issued from the DOD CA.'
  desc 'check', 'Navigate to Tools >> Options >> Advanced >> Certificates tab >> View Certificates button. On the Certificate Manager window, select the "Authorities" tab. Scroll through the Certificate Name list to the U.S. Government heading. Look for the entries for DoD Root CA 2, DoD Root CA 3, and DoD Root CA 4.

If there are entries for DoD Root CA 2, DoD Root CA 3, and DoD Root CA 4, select them individually.

Click the "View" button.

Verify the publishing organization is "US Government."

If there are no entries for the DoD Root CA 2, DoD Root CA 3, and DoD Root CA 4, this is a finding.

Note: In a Windows environment, use of policy setting "security.enterprise_roots.enabled=true" will point Firefox to the Windows Trusted Root Certification Authority Store, this is not a finding.'
  desc 'fix', 'Install the DOD root certificates.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24852r531353_chk'
  tag severity: 'medium'
  tag gid: 'V-223179'
  tag rid: 'SV-223179r612236_rule'
  tag stig_id: 'DTBG010'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-24840r531354_fix'
  tag 'documentable'
  tag legacy: ['SV-33373', 'V-6318']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
