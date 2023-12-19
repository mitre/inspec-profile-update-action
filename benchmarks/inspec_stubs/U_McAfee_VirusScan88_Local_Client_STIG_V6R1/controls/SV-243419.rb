control 'SV-243419' do
  title 'McAfee VirusScan Access Protection Rules Common Standard Protection must be set to block and report when common programs are run from the Temp folder.'
  desc %q(This rule will block any common programs from running from the Temp directory; however, this rule is much more restrictive in that it stops nearly all processes from launching in the Temp folder. Most viruses need to be run once by a person before infecting a computer. This can be done in many ways, such as opening an executable attachment in an email or downloading a program from the Internet. An executable needs to exist on the disk before Windows can run it. A common way for applications to achieve this is to save the file in the user's or system's Temp directory and then run it. One purpose of this rule is to enforce advice that is frequently given to users: "do not open attachments from email." The other purpose of this rule is to close security holes introduced by application bugs. Older versions of Outlook and Internet Explorer are notorious for automatically executing code without the user needing to do anything but preview an email or view a website.)
  desc 'check', 'Note: If the HIPS signatures 7010 and 7035 are enabled to provide this same protection, this check is Not Applicable.Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.

Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". 

Ensure the "Prevent common programs from running files from the Temp folder" (Block and Report) option is selected.

Criteria:  If the "Prevent common programs from running files from the Temp folder" (Block and Report) option is selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.

Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Select the "Prevent common programs from running files from the temp folder" (Block and Report) option.

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46694r722594_chk'
  tag severity: 'medium'
  tag gid: 'V-243419'
  tag rid: 'SV-243419r722596_rule'
  tag stig_id: 'DTAM145'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46651r722595_fix'
  tag 'documentable'
  tag legacy: ['V-6592', 'SV-56391']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
