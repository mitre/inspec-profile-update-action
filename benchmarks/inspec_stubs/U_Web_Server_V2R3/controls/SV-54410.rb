control 'SV-54410' do
  title 'The web server must restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether the web server has been configured to limit the ability of the web server to be used in a DoS attack.

If not, this is a finding.'
  desc 'fix', 'Configure the web server to limit the ability of users to use the web server in a DoS attack.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41833'
  tag rid: 'SV-54410r3_rule'
  tag stig_id: 'SRG-APP-000246-WSR-000149'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-47292r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
