control 'SV-258961' do
  title 'The vCenter server must require authentication for published content libraries.'
  desc 'In the vSphere Client, you can create a local or a subscribed content library. By using content libraries, you can store and manage content in one vCenter Server instance. Alternatively, you can distribute content across vCenter Server instances to increase consistency and facilitate the deployment workloads at scale. When publishing a content library it can be protected by requiring authentication for subscribers.'
  desc 'check', 'From the vSphere Client, go to Content Libraries.

Review the "Password Protected" column.

If a content library is published and is not password protected, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Content Libraries.

Select the target content library.

Select "Actions" then "Edit Settings".

Click the checkbox to "Enable user authentication for access to this content library".

Enter and confirm a password for the content library. Click "OK".

Note: Any subscribed content libraries will need to be updated to enable authentication and provide the password.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62701r934539_chk'
  tag severity: 'medium'
  tag gid: 'V-258961'
  tag rid: 'SV-258961r934541_rule'
  tag stig_id: 'VCSA-80-000295'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62610r934540_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
