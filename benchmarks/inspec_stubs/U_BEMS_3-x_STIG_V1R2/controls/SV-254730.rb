control 'SV-254730' do
  title 'If the BlackBerry Connect service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to enable the Web Proxy.'
  desc 'The web proxy provides a secure gateway for the BlackBerry Connect service so that BEMS can securely connect to the internet.'
  desc 'check', 'This requirement is not applicable if the Connect service is not enabled on BEMS.

Verify that Web Proxy Configuration has been configured.

1. Under "BlackBerry Services Configuration" select "Connect".
2. Select "Web Proxy".
3. Confirm "Use Web Proxy" has been checked.

If "Use Web Proxy" has not been selected, this is a finding.'
  desc 'fix', 'Configure Web Proxy Configuration for the Connect service. 

1. In the BEMS dashboard under "BlackBerry Services Configuration" click "Connect".
2. Click "Web Proxy".
3. Check the box for "Use Web Proxy".
4. Add "Proxy Address".
5. Add "Proxy Port".
6. Set "Proxy Server Authentication Type" to "Digest".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58341r861913_chk'
  tag severity: 'medium'
  tag gid: 'V-254730'
  tag rid: 'SV-254730r879887_rule'
  tag stig_id: 'BEMS-03-014900'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58287r861914_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
