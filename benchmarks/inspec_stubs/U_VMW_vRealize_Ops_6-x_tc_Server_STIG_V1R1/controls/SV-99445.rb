control 'SV-99445' do
  title 'tc Server CaSa must perform server-side session management.'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If an attacker can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications.

Session cookies stored on the server are more secure than cookies stored on the client. Therefore, tc Server must be configured correctly in order to generate and manage session cookies on the server. Managing cookies on the server provides a layer of defense to vRealize Automation.

By default, tc Server is designed to manage cookies on the server. However, incorrect configuration can turn off the default feature.'
  desc 'check', "At the command prompt, execute the following command:

grep -E 'cookies=.false' /usr/lib/vmware-casa/casa-webapp/conf/context.xml

If the command produces any output, this is a finding."
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/context.xml.

Navigate to and locate the <Context> node.

Remove the value 'cookies="false"' from the <Context> node.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88487r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88795'
  tag rid: 'SV-99445r1_rule'
  tag stig_id: 'VROM-TC-000055'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-95537r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
