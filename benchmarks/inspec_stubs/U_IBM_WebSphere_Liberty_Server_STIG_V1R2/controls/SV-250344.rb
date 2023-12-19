control 'SV-250344' do
  title 'The server.xml file must be protected from unauthorized modification.'
  desc 'When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software, and/or application server configuration could potentially have significant adverse effects on the overall security of the system.

Protect the server.xml file from unauthorized modification by applying file permission restrictions.'
  desc 'check', 'As a privileged user with local file access to ${server.config.dir}/server.xml, verify the server.xml file permissions are set to 660.

If the server.xml file permissions are not set to 660, this is a finding.'
  desc 'fix', 'As a privileged user with local file access to ${server.config.dir}/server.xml.

Use the chmod command to configure the correct file permissions of 660.

chmod 660 server.xml'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53779r795083_chk'
  tag severity: 'medium'
  tag gid: 'V-250344'
  tag rid: 'SV-250344r850902_rule'
  tag stig_id: 'IBMW-LS-000910'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-53733r795084_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
