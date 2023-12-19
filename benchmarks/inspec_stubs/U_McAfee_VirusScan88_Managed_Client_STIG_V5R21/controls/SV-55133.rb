control 'SV-55133' do
  title 'The antivirus signature file age must not exceed 7 days.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system.'
  desc 'check', %q(Guidance in DTAM016 requires updates be run daily, automatically or manually. If compliant, the DAT date will be within 24-48 hours old. Since automated update tasks’ success is not guaranteed, the expectation is for update task success to be frequently monitored and corrected when unsuccessful. To allow for that correction, the minimum acceptable threshold for DAT date is not to exceed 7 days. 

On the client machine, right-click on the McAfee red shield icon in the taskbar. 

Choose "About".

Scroll down to the "McAfee VirusScan Enterprise + AntiSpyware Enterprise" section.

Review the date for "DAT Created On:". 

Criteria:  If the "DAT Created On:" date is older than 7 days from the current date, this is a finding.

From the ePO server console System Tree, select the "Systems" tab, select the asset to be checked, and double-click to open its properties. Under the System Information, scroll down to the VirusScan Enterprise section and click on the "More" link in the top-right portion of the VirusScan Enterprise section. Scroll down to the General section and confirm the DAT Date reflected is within the last 7 days.

Criteria: If the DAT Date is older than 7 days from the current date, this is a finding.

NOTE:  If the vendor or trusted site's files are also older than 7 days and match the date of the signature files on the machine, this is not a finding.)
  desc 'fix', 'Update client machines via ePO client task. If this fails to update the client, update antivirus signature files as your local process describes (e.g., auto update or runtime executable.)'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48771r13_chk'
  tag severity: 'high'
  tag gid: 'V-19910'
  tag rid: 'SV-55133r2_rule'
  tag stig_id: 'DTAG008'
  tag gtitle: 'DTAG008 - The antivirus signature file age exceeds 7 days.'
  tag fix_id: 'F-47990r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
