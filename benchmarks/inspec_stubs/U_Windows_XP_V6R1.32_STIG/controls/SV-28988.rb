control 'SV-28988' do
  title 'Unauthorized users are granted right to Act as part of the operating system.'
  desc 'This is a Category 1 finding because users and user groups that are assigned this right can bypass all security protective mechanisms that apply to all users, including administrators.  Accounts with this right should have passwords with the maximum length and be kept in a locked container accessible only by the IAO and his designated backup. 

Some applications require this right to function.  Any exception needs to be documented with the IAO.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> User Rights Assignment.

If any user accounts, or groups (to include administrators),are granted the right "Act as part of the operating system", then this is a finding.
 
 
Documentable Explanation: Some applications require this right to function. Any exception needs to be documented with the IAO.  Acceptable forms of documentation include vendor published documents and application owner confirmation.'
  desc 'fix', 'Configure the system to prevent unauthorized users to "Act as part of the operating system".'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-378r1_chk'
  tag severity: 'high'
  tag gid: 'V-1102'
  tag rid: 'SV-28988r1_rule'
  tag gtitle: 'User Right - Act as part of OS'
  tag fix_id: 'F-5745r1_fix'
  tag potential_impacts: 'Removing application accounts from this right may cause the applications to stop functioning.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
end
