control 'SV-258965' do
  title 'The vCenter Server must remove unauthorized port mirroring sessions on distributed switches.'
  desc 'The vSphere Distributed Virtual Switch can enable port mirroring sessions allowing traffic to be mirrored from one source to a destination. If port mirroring is configured unknowingly this could allow an attacker to observe network traffic of virtual machines.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Configure >> Settings >> Port Mirroring.

Review any configured "Port Mirroring" sessions.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDSwitch | select Name,@{N="Port Mirroring Sessions";E={$_.ExtensionData.Config.VspanSession.Name}}

If there are any unauthorized port mirroring sessions configured, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Configure >> Settings >> Port Mirroring.

Select the unauthorized "Port Mirroring" session and click "Remove". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62705r934551_chk'
  tag severity: 'medium'
  tag gid: 'V-258965'
  tag rid: 'SV-258965r934553_rule'
  tag stig_id: 'VCSA-80-000300'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62614r934552_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
