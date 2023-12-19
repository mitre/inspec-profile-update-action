control 'SV-53037' do
  title 'The web server must use encryption strength in accordance with the categorization of data hosted by the web server when remote connections are provided.'
  desc 'The web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

Methods of communication are http for publicly displayed information, https to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.'
  desc 'check', 'Review the web server documentation and configuration to determine the communication methods that are being used.

Verify the encryption being used is in accordance with the categorization of data being hosted when remote connections are provided.

If it is not, then this is a finding.'
  desc 'fix', 'Configure the web server to use encryption strength equal to the categorization of data hosted when remote connections are provided.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-47343r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40800'
  tag rid: 'SV-53037r3_rule'
  tag stig_id: 'SRG-APP-000014-WSR-000006'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-45963r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
