control 'SV-243073' do
  title 'The vCenter Server must not automatically refresh client sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. Automatic client session refreshes keep unused sessions online, blocking session timeouts.'
  desc 'check', 'Note: For vCenter Server Windows, this is not applicable.

On the vCenter Server, execute the following command:

#  grep "^refresh\\.rate" /etc/vmware/vsphere-client/webclient.properties

Expected result:

refresh.rate = -1

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vmware/vsphere-ui/webclient.properties. Remove any existing "refresh.rate" line and add the following:

refresh.rate = -1

After editing the file, the vSphere Client service must be restarted.

# service-control --restart vsphere-client'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46348r719460_chk'
  tag severity: 'medium'
  tag gid: 'V-243073'
  tag rid: 'SV-243073r879622_rule'
  tag stig_id: 'VCTR-67-000002'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-46305r719461_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
