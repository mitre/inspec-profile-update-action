control 'SV-243410' do
  title 'McAfee VirusScan  Unwanted Programs Policy must be configured to detect adware.'
  desc 'Adware, like spyware, is, at best, an annoyance by presenting unwanted advertisements to the user of a computer, sometimes in the form of a popup.  At worst, it redirects the user to malicious websites. Detecting and blocking will mitigate the likelihood of users being tricked into visiting sites with malicious content.'
  desc 'check', 'Access the local VirusScan console by clicking on Start->All Programs->McAfee->VirusScan Console.

Under the Task column, find the Unwanted Programs Policy, right-click, and choose Properties.
In the Scan Items tab, ensure the Adware option is selected.

If the Adware option is not selected, this is a finding.
If the Adware option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\NVP

Criteria:  If the value DetectAdware is 1, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking on Start->All Programs->McAfee->VirusScan Console.

Under the Task column, find the Unwanted Programs Policy, right-click, and choose Properties.
In the Scan Items tab, select the Adware option.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46685r722567_chk'
  tag severity: 'medium'
  tag gid: 'V-243410'
  tag rid: 'SV-243410r722569_rule'
  tag stig_id: 'DTAM136'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46642r722568_fix'
  tag 'documentable'
  tag legacy: ['V-35027', 'SV-56405']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
