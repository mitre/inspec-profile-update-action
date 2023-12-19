control 'SV-214344' do
  title 'The Apache web server must be configured to immediately disconnect or disable remote access to the hosted applications.'
  desc 'During an attack on the Apache web server or any of the hosted applications, the system administrator may need to disconnect or disable access by users to stop the attack.

The Apache web server must be configured to disconnect users to a hosted application without compromising other hosted applications unless deemed necessary to stop the attack. Methods to disconnect or disable connections are to stop the application service for a specified hosted application, stop the Apache web server, or block all connections through the Apache web server access list.

The Apache web server capabilities used to disconnect or disable users from connecting to hosted applications and the Apache web server must be documented to make certain that, during an attack, the proper action is taken to conserve connectivity to any other hosted application if possible and to make certain log data is conserved for later forensic analysis.'
  desc 'check', 'Interview the System Administrator and Web Manager.

Ask for documentation for the Apache web server administration.

Verify there are documented procedures for shutting down an Apache website in the event of an attack. The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Stop the Apache service.

If the web server is not capable of or cannot be configured to disconnect or disable remote access to the hosted applications when necessary, this is a finding.'
  desc 'fix', 'Prepare documented procedures for shutting down an Apache website in the event of an attack.

The procedure should, at a minimum, provide the following step:

Stop the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15556r277535_chk'
  tag severity: 'medium'
  tag gid: 'V-214344'
  tag rid: 'SV-214344r505936_rule'
  tag stig_id: 'AS24-W1-000680'
  tag gtitle: 'SRG-APP-000316-WSR-000170'
  tag fix_id: 'F-15554r277536_fix'
  tag 'documentable'
  tag legacy: ['SV-102529', 'V-92441']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
