control 'SV-218826' do
  title 'The IIS 10.0 websites MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a Denial of Service (DoS) attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).'
  desc 'check', 'Access the IIS 10.0 IIS Manager.

Click the IIS 10.0 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Review the results and verify the value is greater than zero for the "maxconnections" parameter.

If the maxconnections parameter is set to zero, this is a finding.'
  desc 'fix', 'Access the IIS 10.0 IIS Manager.

Click the IIS 10.0 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Set the "maxconnections" parameter to a value greater than zero.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20298r310953_chk'
  tag severity: 'medium'
  tag gid: 'V-218826'
  tag rid: 'SV-218826r561041_rule'
  tag stig_id: 'IIST-SV-000200'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-20296r310954_fix'
  tag 'documentable'
  tag legacy: ['SV-109291', 'V-100187']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
