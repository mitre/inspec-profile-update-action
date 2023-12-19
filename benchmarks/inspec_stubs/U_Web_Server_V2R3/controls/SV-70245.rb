control 'SV-70245' do
  title 'The web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. 

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine which ports and protocols are enabled.

Verify that the ports and protocols being used are permitted, necessary for the operation of the web server and the hosted applications and are secure for a production system.

If any of the ports or protocols are not permitted, are nonsecure or are not necessary for web server operation, this is a finding.'
  desc 'fix', 'Configure the web server to disable any ports or protocols that are not permitted, are nonsecure for a production web server or are not necessary for web server operation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56561r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55991'
  tag rid: 'SV-70245r2_rule'
  tag stig_id: 'SRG-APP-000383-WSR-000175'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-60869r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
