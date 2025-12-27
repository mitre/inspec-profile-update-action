control 'SV-32323' do
  title 'Web sites must limit the number of simultaneous requests.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web-site, facilitating a Denial of Service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).'
  desc 'check', '1. Open an administrator command prompt.
2. CD \\Windows\\system32\\inetsrv
3. Enter the command:
appcmd list config /section:system.applicationHost/sites > out.txt (opens output in Notepad).
4. Review the results and verify each website has a value greater than zero listed for maxconnections parameter.

If not, this is a finding.

If nothing is listed, this is also a finding.'
  desc 'fix', %q(For the site under review, determine the maximum number of connections needed.

1. Open an administrator command prompt.
2. CD \Windows\system32\inetserv
3. Enter the command:
appcmd set config -section:system.applicationHost/sites "/[name='Default Web Site'].limits.maxConnections:X" /commit:apphost

Note: Replace SITENAME with the site under review and X with the maximum number of connections allowable.

4. Enter the command to verify changes:
appcmd list config –section:system.applicationHost/sites>out.txt (opens output in Notepad).)
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32730r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2240'
  tag rid: 'SV-32323r6_rule'
  tag stig_id: 'WG110 IIS7'
  tag gtitle: 'WG110'
  tag fix_id: 'F-29195r6_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
