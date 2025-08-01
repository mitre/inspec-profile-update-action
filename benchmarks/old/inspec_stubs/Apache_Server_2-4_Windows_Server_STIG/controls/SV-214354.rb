control 'SV-214354' do
  title 'The Apache web server must be tuned to handle the operational requirements of the hosted application.'
  desc 'A denial of service (DoS) can occur when the Apache web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the Apache web server must be tuned to handle the expected traffic for the hosted applications.'
  desc 'check', 'Verify the "Timeout" directive is specified in the Apache configuration files to have a value of "10" seconds or less.

If the "Timeout" directive is not configured or set for more than "10" seconds, this is a finding.'
  desc 'fix', 'Add or modify the "Timeout" directive in the Apache configuration to have a value of "10" seconds or less.

"Timeout 10"

Restart the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15566r277565_chk'
  tag severity: 'medium'
  tag gid: 'V-214354'
  tag rid: 'SV-214354r879806_rule'
  tag stig_id: 'AS24-W1-000830'
  tag gtitle: 'SRG-APP-000435-WSR-000148'
  tag fix_id: 'F-15564r277566_fix'
  tag 'documentable'
  tag legacy: ['SV-102553', 'V-92465']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
