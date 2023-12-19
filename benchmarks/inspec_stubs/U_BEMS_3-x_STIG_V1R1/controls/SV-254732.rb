control 'SV-254732' do
  title 'If the BlackBerry Docs service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to enable the proxy server authentication type (if a proxy is used).'
  desc 'The web proxy provides a secure gateway for the BlackBerry Docs service so that BEMS can securely connect to enterprise servers.'
  desc 'check', 'This requirement is not applicable if the Docs service for BEMS is not enabled.

Verify that the authentication type is set to NTLM if a web proxy is used.

1. Under the "BlackBerry Services Configuration", select "Docs".
2. Under the "Proxy Server Authentication Type", ensure "NTLM" is Selected. 

If "NTLM" is not selected, this is a finding.'
  desc 'fix', 'Configure the Docs Web Proxy Authentication type within BEMS.

1. Under the "BlackBerry Services Configuration", select "Docs".
2. Select "Web Proxy Configuration".
3. Under "Proxy Server Authentication Type" Select "NTLM".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58343r861919_chk'
  tag severity: 'medium'
  tag gid: 'V-254732'
  tag rid: 'SV-254732r861921_rule'
  tag stig_id: 'BEMS-03-015100'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58289r861920_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
