control 'SV-32635' do
  title 'The web server must use a vendor-supported version of the web server software.'
  desc 'Several vulnerabilities are associated with older versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software.  Maintaining the web server at a current version makes the efforts of a malicious user more difficult.'
  desc 'check', '1. Open the IIS Manager.
2. Click Help, and select About Internet Information Services.
3. If the version is less than 7.0, this is a finding.'
  desc 'fix', 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  impact 0.7
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32930r1_chk'
  tag severity: 'high'
  tag gid: 'V-2246'
  tag rid: 'SV-32635r2_rule'
  tag stig_id: 'WG190 IIS7'
  tag gtitle: 'WG190'
  tag fix_id: 'F-2295r5_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
