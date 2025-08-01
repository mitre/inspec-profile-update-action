control 'SV-243075' do
  title 'The vCenter Server must terminate management sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.'
  desc 'check', 'Note: For vCenter Server Windows, this is not applicable.

On the vCenter Server, execute the following command:

#  grep "^session\\.timeout" /etc/vmware/vsphere-client/webclient.properties

Expected result:

session.timeout = 10

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vmware/vsphere-client/webclient.properties. Remove any existing "session.timeout" line and add the following:

session.timeout = 10'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46350r719466_chk'
  tag severity: 'medium'
  tag gid: 'V-243075'
  tag rid: 'SV-243075r879622_rule'
  tag stig_id: 'VCTR-67-000004'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-46307r719467_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
