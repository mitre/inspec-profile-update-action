control 'SV-54188' do
  title 'The web server must initiate session logging upon start up.'
  desc 'An attacker can compromise a web server during the startup process. If logging is not initiated until all the web server processes are started, key information may be missed and not available during a forensic investigation. To assure all logable events are captured, the web server must begin logging once the first web server process is initiated.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server captures log data as soon as the web server is started.

If the web server does not capture logable events upon startup, this is a finding.'
  desc 'fix', 'Configure the web server to capture logable events upon startup.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48040r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41611'
  tag rid: 'SV-54188r3_rule'
  tag stig_id: 'SRG-APP-000092-WSR-000055'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag fix_id: 'F-47070r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
