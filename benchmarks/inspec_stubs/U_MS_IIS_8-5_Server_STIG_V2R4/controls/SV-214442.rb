control 'SV-214442' do
  title 'The IIS 8.5 MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a Denial of Service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).'
  desc 'check', 'Access the IIS 8.5 IIS Manager.

Click the IIS 8.5 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Review the results and verify the value is greater than zero for the "maxconnections" parameter.

If the maxconnections parameter is set to zero, this is a finding.'
  desc 'fix', 'Access the IIS 8.5 IIS Manager.

Click the IIS 8.5 server.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".

Expand "siteDefaults".
Expand "limits".

Set the "maxconnections" parameter to a value greater than zero.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15652r310374_chk'
  tag severity: 'medium'
  tag gid: 'V-214442'
  tag rid: 'SV-214442r508658_rule'
  tag stig_id: 'IISW-SV-000200'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-15650r310375_fix'
  tag 'documentable'
  tag legacy: ['SV-104771', 'V-95633']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
