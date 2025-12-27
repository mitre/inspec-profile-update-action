control 'SV-32694' do
  title 'The production web-site must configure the Maximum Query String limit.'
  desc 'By setting limits on web requests, it helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks.  The Maximum Query String Request Filter describes the upper limit on allowable query string lengths.  Upon exceeding the configured value, IIS will generate a Status Code 404.15.'
  desc 'check', 'For each site reviewed: 
1. Open the IIS Manager.
2. Click on the site name.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.

If the Maximum Query String value is not set to 2048, this is a finding.

NOTE: If the site has operational reasons to set Maximum Query String to an alternate value, and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
5. Set the Maximum Query String value to 2048.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32891r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26043'
  tag rid: 'SV-32694r3_rule'
  tag stig_id: 'WA000-WI6230'
  tag gtitle: 'WA000-WI6230'
  tag fix_id: 'F-29037r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
