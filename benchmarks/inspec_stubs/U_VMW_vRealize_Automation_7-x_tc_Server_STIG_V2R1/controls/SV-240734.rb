control 'SV-240734' do
  title 'tc Server HORIZON must perform server-side session management.'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If an attacker can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications. 

Session cookies stored on the server are more secure than cookies stored on the client. Therefore, tc Server must be configured correctly in order to generate and manage session cookies on the server. Managing cookies on the server provides a layer of defense to vRealize Automation.

By default, tc Server is designed to manage cookies on the server. However, incorrect configuration can turn off the default feature.'
  desc 'check', "At the command prompt, execute the following command:

grep -E 'cookies=.false' /opt/vmware/horizon/workspace/conf/context.xml

If the command produces any output, this is a finding."
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/context.xml.

Navigate to and locate the <Context> node.

Remove the value 'cookies="false"' from the <Context> node.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43967r673944_chk'
  tag severity: 'medium'
  tag gid: 'V-240734'
  tag rid: 'SV-240734r673946_rule'
  tag stig_id: 'VRAU-TC-000050'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-43926r673945_fix'
  tag 'documentable'
  tag legacy: ['SV-100549', 'V-89899']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
