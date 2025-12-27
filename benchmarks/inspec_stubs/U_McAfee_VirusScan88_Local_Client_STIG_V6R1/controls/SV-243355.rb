control 'SV-243355' do
  title 'The antivirus signature file age must not exceed 7 days.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system.'
  desc 'check', %q(Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.

Click Help >> About VirusScan Enterprise.

The "About" dialog box will be displayed, showing, among other information, the current DAT version installed and the date of that DAT version.

Guidance in DTAM016 requires updates be run daily, automatically or manually. If compliant, the DAT date will be within 24-48 hours old. Since automated update tasks' success is not guaranteed, the expectation is for update task success to be frequently monitored and corrected when unsuccessful. To allow for that correction, the minimum acceptable threshold for DAT date is not to exceed 7 days. 

If the DAT date displayed is more than "7" days old, this is a finding.

If the vendor or trusted site's files match the date of the signature files on the machine, this is not a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.

Under the Task column, select the AutoUpdate option, right-click, and select "Start".'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46630r722665_chk'
  tag severity: 'high'
  tag gid: 'V-243355'
  tag rid: 'SV-243355r722666_rule'
  tag stig_id: 'DTAG008'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-46587r722403_fix'
  tag 'documentable'
  tag legacy: ['V-6596', 'SV-56392']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
