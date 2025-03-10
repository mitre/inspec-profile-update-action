control 'SV-32754' do
  title 'The MultiViews directive must be disabled.'
  desc '<0> [object Object]'
  desc 'check', 'To view the MultiViews value enter the following command:

grep "MultiView" /usr/local/apache2/conf/httpd.conf.

Review all uncommented Options statements for the following value: -MultiViews 

If the value is found on the Options statement, and it does not have a preceding ‘-‘, this is a finding. 

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.'
  desc 'fix', 'Edit the httpd.conf file and add the "-" to the MultiViews setting, or set the options directive to None.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33616r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13734'
  tag rid: 'SV-32754r1_rule'
  tag stig_id: 'WA000-WWA056 A22'
  tag gtitle: 'WA000-WWA056'
  tag fix_id: 'F-29247r1_fix'
end
