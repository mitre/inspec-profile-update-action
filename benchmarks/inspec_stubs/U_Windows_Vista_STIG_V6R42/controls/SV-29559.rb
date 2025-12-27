control 'SV-29559' do
  title 'The HBSS McAfee Agent is not installed.'
  desc 'check', 'Verify the following file is installed and at a version listed or above:
McAfee Agent v5.x - masvc.exe
McAfee Agent v4.x - FrameworkService.exe
The default location is C:\\Program Files (x86)\\McAfee\\Common Framework\\
If the McAfee Agent file is not found or at a version specified or above, this is a finding.

Run "Services.msc".
Verify the corresponding service is running.
McAfee Agent v5.x - McAfee Agent Service
McAfee Agent v4.x - McAfee Framework Service
If the service does not have a Status of "Started", this is a finding.'
  desc 'fix', 'Deploy the McAfee Agent as detailed in accordance with the DoD HBSS STIG.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-71147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15505'
  tag rid: 'SV-29559r2_rule'
  tag gtitle: 'HBSS McAfee Agent'
  tag fix_id: 'F-76991r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
