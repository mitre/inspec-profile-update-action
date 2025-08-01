control 'SV-93729' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must be configured to use HTTPS.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission to web applications. This is usually achieved through the use of HTTPS.'
  desc 'check', 'Verify BEMS has been configured to use HTTPS as follows:

1. In the BEMS Dashboard, under "BEMS System Settings", click "BEMS Configuration".
2. Click "BlackBerry Dynamics".
3. In the Protocol drop-down list, verify "HTTPS" is selected.

If HTTPS is not configured on BEMS, this is a finding.'
  desc 'fix', 'Configure BEMS to use HTTPS as follows:

1. In the BEMS Dashboard, under "BEMS System Settings", click "BEMS Configuration".
2. Click "BlackBerry Dynamics".
3. In the Protocol drop-down list, select "HTTPS".'
  impact 0.7
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78611r1_chk'
  tag severity: 'high'
  tag gid: 'V-79023'
  tag rid: 'SV-93729r1_rule'
  tag stig_id: 'BEMS-00-013500'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85773r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
