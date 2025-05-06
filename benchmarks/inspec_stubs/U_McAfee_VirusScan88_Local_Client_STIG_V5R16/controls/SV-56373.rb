control 'SV-56373' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to log the session summary.'
  desc 'Log management is essential to ensuring computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Ensure the "Session summary" option is selected.

Criteria:  If the "Session summary" option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bLogSummary is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Select the "Session summary" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6478'
  tag rid: 'SV-56373r1_rule'
  tag stig_id: 'DTAM012'
  tag gtitle: 'DTAM012-McAfee VirusScan log summary parameter'
  tag fix_id: 'F-49055r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
