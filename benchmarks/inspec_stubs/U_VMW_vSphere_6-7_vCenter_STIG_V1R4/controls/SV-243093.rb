control 'SV-243093' do
  title 'The vCenter Server must enable all tasks to be shown to Administrators in the Web Client.'
  desc "By default, not all tasks are shown in the Web Client to Administrators, and only that user's tasks will be shown. Enabling all tasks to be shown will allow the Administrator to potentially see any malicious activity they may miss with the view disabled."
  desc 'check', 'Note: For vCenter Server Windows, this is not applicable.

On the vCenter Server, execute the following command:

#  grep "^show\\.allusers\\.tasks" /etc/vmware/vsphere-client/webclient.properties

Expected result:

show.allusers.tasks = true

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vmware/vsphere-client/webclient.properties. Remove any existing "show.allusers.tasks" line and add the following:

show.allusers.tasks = true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46368r719520_chk'
  tag severity: 'medium'
  tag gid: 'V-243093'
  tag rid: 'SV-243093r879887_rule'
  tag stig_id: 'VCTR-67-000029'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46325r719521_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
