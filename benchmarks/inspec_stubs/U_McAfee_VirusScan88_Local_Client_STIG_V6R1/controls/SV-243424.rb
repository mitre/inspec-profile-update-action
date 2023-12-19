control 'SV-243424' do
  title 'McAfee VirusScan Access Protection Rules Anti-Virus Standard Protection must be set to prevent mass mailing worms from sending mail.'
  desc 'Many viruses and worms find email addresses on the infected system and send themselves to these addresses. They do this by connecting directly to the email servers whose names they have harvested from the local system. This rule prevents any process from talking to a foreign email server using SMTP. By blocking this communication, a machine may become infected with a new mass-mailing virus, but that virus will be unable to spread further by email. It prevents outbound access to SMTP ports 25 and 587 on all programs except known email clients listed as an exclusion.'
  desc 'check', 'NOTE: If the system being reviewed has the function of sending email via the SMTP protocol, this setting is not applicable.

NOTE: Since there is no HIPS signature to provide this same protection, this check is applicable even if HIPS is enabled.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Ensure "Prevent mass mailing worms from sending email" (Block and Report) options are both selected. Click Edit. Under the "Processes to exclude:" section, verify no processes are listed. If any processes are listed, they must be documented with, and approved by, the IAO/IAM.

Criteria:  
If "Prevent mass mailing worms from sending email" (Block and Report) options are not both selected. This is a finding.
If "Prevent mass mailing worms from sending email" (Block and Report) options are both selected, and any listed "Processes to exclude:" are approved by the IAO/IAM, this is not a finding.
If "Prevent mass mailing worms from sending email" (Block and Report) options are both selected, but listed "Processes to exclude:" have not been approved by the IAO/IAM, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Select both "Prevent mass mailing worms from sending email" (Block and Report) options. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46699r722609_chk'
  tag severity: 'medium'
  tag gid: 'V-243424'
  tag rid: 'SV-243424r722611_rule'
  tag stig_id: 'DTAM150'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-46656r722610_fix'
  tag 'documentable'
  tag legacy: ['V-14663', 'SV-56411']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
