control 'SV-243409' do
  title 'McAfee VirusScan  Unwanted Programs Policy must be configured to detect spyware.'
  desc "Spyware is software that aids in gathering information about a person or organization without their knowledge, and that may send such information to another entity without the consumer's consent, or that asserts control over a computer without the user's knowledge. Spyware may try to deceive users by bundling itself with desirable software. A spyware infestation can create significant unwanted CPU activity, disk usage, and network traffic. Some types of spyware disable software firewalls and antivirus software. Detecting, blocking, and eradicating malicious spyware or preventing it from being installed will alleviate the negative side effects of the spyware."
  desc 'check', 'Access the local VirusScan console by clicking on Start->All Programs->McAfee->VirusScan Console.

Under the Task column, find the Unwanted Programs Policy, right-click, and choose Properties.
In the Scan Items tab, ensure the Spyware option is selected.

If the Spyware option is not selected, this is a finding.
If the Spyware option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\NVP

Criteria:  If the value DetectSpyware is 1, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking on Start->All Programs->McAfee->VirusScan Console.

Under the Task column, find the Unwanted Programs Policy, right-click, and choose Properties.
In the Scan Items tab, select the Spyware option.

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46684r722564_chk'
  tag severity: 'medium'
  tag gid: 'V-243409'
  tag rid: 'SV-243409r722566_rule'
  tag stig_id: 'DTAM135'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46641r722565_fix'
  tag 'documentable'
  tag legacy: ['V-14661', 'SV-56418']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
