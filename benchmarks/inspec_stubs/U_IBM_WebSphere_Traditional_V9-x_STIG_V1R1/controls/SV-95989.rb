control 'SV-95989' do
  title 'The WebSphere Application Server must remove JREs left by web server and plug-in installers for web servers and plugins running in the DMZ.'
  desc 'When you install IBM HTTP Server, the installer leaves behind a JRE. Remove this JRE, as it provides functions that are not needed by the Web server or plug-in under normal conditions. Keep in mind that this will make it impossible to run some tools such as ikeyman on this Web server. 

When you install the WebSphere Application Server HTTP Server plug-in using the IBM installer, it also leaves behind a JRE. Also, remove this JRE post install.

Having a functioning JRE in the DMZ provides attackers who have breached into the DMZ with additional tools to carry out further attacks.'
  desc 'check', 'This check needs to be run on the web server operating in the DMZ.

Review system documentation.

Identify web servers operating in DMZ.

If there are no web servers configured for the DMZ, this is not applicable.

From the administrative console, select Server Types >> Web Servers.

Select each web server operating in the DMZ.

Identify the "Web server installation location". 

Open a secured command shell to the web server in the DMZ.

Change directory to the web server installation location.

CD to the /plugins folder. 

If a /java directory exists in the plugins folder, this is a finding.'
  desc 'fix', 'For web servers provided with the WebSphere installation that are operating in the DMZ.

Remove the /java directory from within the plugins folder.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80973r2_chk'
  tag severity: 'low'
  tag gid: 'V-81275'
  tag rid: 'SV-95989r1_rule'
  tag stig_id: 'WBSP-AS-000940'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-88055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
