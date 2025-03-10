control 'SV-100897' do
  title 'The vAMI configuration file must be protected from unauthorized access.'
  desc "When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software and/or application server configuration can potentially have significant effects on the overall security of the system. Access restrictions for changes also include application software libraries. If the application server provides automatic code deployment capability, (where updates to applications hosted on the application server are automatically performed, usually by the developers' IDE tool), it must also provide a capability to restrict the use of automatic application deployment. Automatic code deployments are allowable in a development environment, but not in production."
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /opt/vmware/etc/sfcb/sfcb.cfg

If the permissions on the sfcb.cfg file are greater than 640, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod 640 /opt/vmware/etc/sfcb/sfcb.cfg'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89939r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90247'
  tag rid: 'SV-100897r1_rule'
  tag stig_id: 'VRAU-VA-000460'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-96989r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
