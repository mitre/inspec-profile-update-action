control 'SV-243434' do
  title 'McAfee VirusScan Access Protection Properties must be configured to enable access protection.'
  desc 'Access Protection prevents unwanted changes to a computer by restricting access to specified ports, files and folders, shares, and registry keys and values. It prevents users from stopping McAfee processes and services, which are critical before and during outbreaks. Access Protection for VSE uses predefined and user-defined rules to strengthen systems against virus attacks. For instance, rules are used to specify which items can and cannot be accessed. Each rule can be configured to block and/or report access violations when they occur, and rules can also be disabled.'
  desc 'check', 'NOTE: Access Protection must be enabled in order to afford protection identified in DTAM150 and DTAM151. 

If HIPS signatures are enabled to provide the same protection as DTAM138, DTAM139, DTAM140, DTAM141, DTAM142, DTAM143, DTAM144, DTAM145, DTAM146, DTAM147, DTAM148 and DTAM149, those checks may be individually marked as not applicable.


Under the Access Protection tab, ensure the "Enable Access Protection" option is selected.

Criteria:  If the "Enable Access Protection" option is not selected, this is a finding. 

On the client machine use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value APEnabled is not set to "1", this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, select the "Enable Access Protection" option. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46709r722639_chk'
  tag severity: 'medium'
  tag gid: 'V-243434'
  tag rid: 'SV-243434r722641_rule'
  tag stig_id: 'DTAM161'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46666r722640_fix'
  tag 'documentable'
  tag legacy: ['V-59365', 'SV-73795']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
