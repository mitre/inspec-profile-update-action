control 'SV-29341' do
  title 'Systems must be at supported service packs (SP) or releases levels.'
  desc 'Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities and leaves them subject to exploitation.   Systems must be maintained at a service pack level supported by the vendor with new security updates.'
  desc 'check', 'From the menu bar click “Start” and then “Run”.
Type “winver.exe” in the dialog box and click OK. 
If the "About Windows" box displays the following Service Pack(s), then this is a finding.

Unsupported Service Packs:
Windows Vista – any prior to SP2

Support of SP1 for Windows Vista ended 12 July 2011.'
  desc 'fix', 'Update the system to a supported service pack.

Application of new service packs should be thoroughly tested before deploying in a production environment.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-34622r1_chk'
  tag severity: 'high'
  tag gid: 'V-1073'
  tag rid: 'SV-29341r1_rule'
  tag gtitle: 'Unsupported Service Packs'
  tag fix_id: 'F-30098r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
