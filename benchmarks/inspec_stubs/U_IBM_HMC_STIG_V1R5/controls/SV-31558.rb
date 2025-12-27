control 'SV-31558' do
  title 'Product engineering access to the Hardware Management Console must be disabled.'
  desc 'The Hardware Management Console has a built-in feature that allows Product Engineers access to the console. With access authority, IBM Product Engineering can log on the Hardware Management Console with an exclusive user identification (ID) that provides tasks and operations for problem determination. Product Engineering access is provided by a reserved password and permanent user ID. You cannot view, discard, or change the password and user ID, but you can control their use for accessing the Hardware Management Console. User IDs and passwords that are hard-coded and cannot be modified are a violation of NIST 800-53 and multiple other compliance regulations. Failure to disable this access would allow unauthorized access and could lead to security violations on the HMC.'
  desc 'check', 'Have the System Administrator or System Programmer validate that IBM Product Engineering access to the Hardware Management Console is disabled. 

This can be checked under the classic style user interface; this task is found under the Hardware Management Console Settings console action.
Open the Customize Product Engineering Access task. The Customize Product Engineering Access window is displayed. 
Select the appropriate accesses for product engineering or remote product engineering. (Both should be disabled.)
Click OK to save the changes and exit the task.

If access to the Customize Product Engineering Access is not disabled, than this is a finding.'
  desc 'fix', 'The System Administrator or System Programmer will set the
Product Engineering Access control for product engineering or remote product engineering to a disabled status.

This can be checked under the classic style user interface; this task is found under the Hardware Management Console Settings console action.
Open the Customize Product Engineering Access task. The Customize Product Engineering Access window is displayed. 
Select the appropriate accesses for product engineering or remote product engineering. (Both should be disabled)
Click OK to save the changes and exit the task.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-31830r1_chk'
  tag severity: 'high'
  tag gid: 'V-25388'
  tag rid: 'SV-31558r2_rule'
  tag stig_id: 'HMC0210'
  tag gtitle: 'HMC0210'
  tag fix_id: 'F-28330r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
