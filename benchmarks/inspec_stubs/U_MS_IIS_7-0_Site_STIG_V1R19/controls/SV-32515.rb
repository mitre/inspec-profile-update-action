control 'SV-32515' do
  title 'The website must have a unique application pool.'
  desc 'Application pools isolate sites and applications to address reliability, availability, and security issues. Sites and applications may be grouped according to configurations, although each site will be associated with a unique application pool.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click the Advanced Settings in the Action Pane.
4. Under the General section review the application pool name.
5. If any websites share an application pool, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click the Advanced Settings in the Action Pane.
4. Under the General section click on the application pool name, then click on the application pool selection button.
5. Select the desired application pool in the application pool dialogue box.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32824r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13703'
  tag rid: 'SV-32515r2_rule'
  tag stig_id: 'WA000-WI6010 IIS7'
  tag gtitle: 'WA000-WI6010'
  tag fix_id: 'F-28935r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
