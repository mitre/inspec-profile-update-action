control 'SV-32644' do
  title 'All web-sites must be assigned a default Host header.'
  desc 'In order to reduce the possibility of DNS rebinding attacks and IP-based scans, all web-sites allowing HTTP/HTTPS over ports 80/443 will be assigned default Host headers.'
  desc 'check', '1. Open the IIS Manager.
2. In the “Connections” pane, expand the “Sites” node in the tree. Select the site name under review.
3. In the “Actions” pane, select “Bindings”.
4. Each site should have a hostname entry (at a minimum) and specific IP addresses assigned to port 80 for HTTP and port 443 for HTTPS. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. In the “Connections” pane, expand the “Sites” node in the tree. Select the site name under review.
3. In the “Actions” pane, select “Bindings”.
4. In the “Site Bindings” dialog box, select the binding to add a host header and then click “Edit” or “Add”.
5. In the “Host” name box, type a host header for the site for both port 80 for HTTP and port 443 for HTTPS.
6. Click “OK”.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32868r3_chk'
  tag severity: 'low'
  tag gid: 'V-6724'
  tag rid: 'SV-32644r4_rule'
  tag stig_id: 'WG520 IIS7'
  tag gtitle: 'WG520'
  tag fix_id: 'F-29019r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
