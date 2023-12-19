control 'SV-223169' do
  title 'Firefox Development Tools Must Be Disabled.'
  desc 'While the risk associated with browser development tools is more related to the proper design of a web application, a risk vector remains within the browser. The developer tools allow end users and application developers to view and edit all types of web application related data via the browser. Page elements, source code, javascript, API calls, application data, etc. may all be viewed and potentially manipulated. Manipulation could be useful for troubleshooting legitimate issues, and this may be performed in a development environment. Manipulation could also be malicious and must be addressed.'
  desc 'check', 'Procedure: Open a browser window, type "about:config" in the address bar. 

Criteria: If the value of "devtools.policy.disabled" is not "true", then this is a finding.'
  desc 'fix', 'Set the value of "devtools.policy.disabled" to "true" using the Mozilla.cfg file, or the registry value of HKLM\\Software\\Policies\\Mozilla\\Firefox\\DisableDeveloperTools to “1”'
  impact 0.3
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24842r531324_chk'
  tag severity: 'low'
  tag gid: 'V-223169'
  tag rid: 'SV-223169r612236_rule'
  tag stig_id: 'DTBF195'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-24830r531325_fix'
  tag 'documentable'
  tag legacy: ['SV-106633', 'V-97529']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
