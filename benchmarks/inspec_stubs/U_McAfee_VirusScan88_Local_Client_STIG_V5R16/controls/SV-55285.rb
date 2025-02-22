control 'SV-55285' do
  title 'McAfee VirusScan Access Protection Rules Common Standard Protection must be set to prevent hooking of McAfee processes.'
  desc 'Hooking covers a range of techniques used to alter or augment the behavior of an operating system, of applications, or of other software components by intercepting function calls or messages or events passed between software components. Code that handles such intercepted function calls, events, or messages is called a "hook". Hooking can also be used by malicious code. For example, rootkits, pieces of software that try to make themselves invisible by faking the output of API calls that would otherwise reveal their existence, often use hooking techniques. This rule prevents other processes from hooking of McAfee processes.'
  desc 'check', 'Note: If the HIPS signature 6051 is enabled to provide this same protection, this check is not applicable. 

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label.  In the "Categories" box, select "Common Standard Protection". Ensure both "Prevent hooking of McAfee processes" (Block and Report) options are both selected.

Criteria:  If "Prevent hooking of McAfee processes" (Block and Report) options are both selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Select both "Prevent hooking of McAfee processes" (Block and Report) options. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49357r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42557'
  tag rid: 'SV-55285r2_rule'
  tag stig_id: 'DTAM146'
  tag gtitle: 'DTAM146 - Access Protection prevent hooking of McAfee processes'
  tag fix_id: 'F-48139r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
