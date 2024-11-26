control 'SV-207505' do
  title 'The VMM must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the VMM after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the VMM.'
  desc 'check', 'Verify the VMM removes all software components after updated versions have been installed.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to remove all software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7762r365919_chk'
  tag severity: 'medium'
  tag gid: 'V-207505'
  tag rid: 'SV-207505r854679_rule'
  tag stig_id: 'SRG-OS-000437-VMM-001760'
  tag gtitle: 'SRG-OS-000437'
  tag fix_id: 'F-7762r365920_fix'
  tag 'documentable'
  tag legacy: ['SV-71571', 'V-57311']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
