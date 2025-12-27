control 'SV-32514' do
  title 'The Content Location header must not contain proprietary IP addresses.'
  desc 'When using static HTML pages, a Content-Location header is added to the response.  The Internet Information Server (IIS) Content-Location may reference the IP address of the server, rather than the Fully Qualified Domain Name (FQDN) or Hostname. This header may expose internal IP addresses that are usually hidden or masked behind a Network Address Translation (NAT) firewall or proxy server. There is a value that can be modified in the IIS metabase to change the default behavior from exposing IP addresses, to sending the FQDN instead.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click Configuration Editor.
4. From the drop-down box select system.webserver serverRuntime.

If alternateHostName has no assigned value, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click Configuration Editor.
4. Click the drop-down box located at the top of the Configuration Editor Pane.
5. Scroll until you find system.webserver/serverRuntime, double-click the element, and add the appropriate value.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32823r1_chk'
  tag severity: 'low'
  tag gid: 'V-13702'
  tag rid: 'SV-32514r2_rule'
  tag stig_id: 'WA000-WI120 IIS7'
  tag gtitle: 'WA000-WI120'
  tag fix_id: 'F-28934r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
