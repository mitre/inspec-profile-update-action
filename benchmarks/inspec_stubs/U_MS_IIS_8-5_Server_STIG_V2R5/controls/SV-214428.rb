control 'SV-214428' do
  title 'The IIS 8.5 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.'
  desc 'During an attack on the web server or any of the hosted applications, the system administrator may need to disconnect or disable access by users to stop the attack.

The web server must provide a capability to disconnect users to a hosted application without compromising other hosted applications unless deemed necessary to stop the attack. Methods to disconnect or disable connections are to stop the application service for a specified hosted application, stop the web server, or block all connections through web server access list.

The web server capabilities used to disconnect or disable users from connecting to hosted applications and the web server must be documented to make certain that, during an attack, the proper action is taken to conserve connectivity to any other hosted application if possible and to make certain log data is conserved for later forensic analysis.'
  desc 'check', 'Interview the System Administrator and Web Manager.

Ask for documentation for the IIS 8.5 web server administration.

Verify there are documented procedures for shutting down an IIS 8.5 website in the event of an attack. The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Access the IIS 8.5 web server IIS Manager.

Select the respective website.

In the "Actions" pane, under "Manage Website", click on "Stop".

If necessary, stop all websites.

If necessary, stop the IIS 8.5 web server by selecting the web server in the IIS Manager.

In the "Actions" pane, under "Manage Server", click on "Stop".

If the web server is not capable of or cannot be configured to disconnect or disable remote access to the hosted applications when necessary, this is a finding.'
  desc 'fix', 'Prepare documented procedures for shutting down an IIS 8.5 website in the event of an attack.

The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Access the IIS 8.5 web server IIS Manager.

Select the respective website. 

In the "Actions" pane, under "Manage Website", click on "Stop".

If necessary, stop all websites.

If necessary, stop the IIS 8.5 web server by selecting the web server in the IIS Manager.

In the "Actions" pane, under "Manage Server", click on "Stop".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15638r310332_chk'
  tag severity: 'medium'
  tag gid: 'V-214428'
  tag rid: 'SV-214428r879693_rule'
  tag stig_id: 'IISW-SV-000143'
  tag gtitle: 'SRG-APP-000316-WSR-000170'
  tag fix_id: 'F-15636r310333_fix'
  tag 'documentable'
  tag legacy: ['SV-91439', 'V-76743']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
