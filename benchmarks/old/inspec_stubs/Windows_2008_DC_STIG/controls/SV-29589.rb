control 'SV-29589' do
  title 'Unapproved Users have access to Debug programs.'
  desc 'This is a Category 1 finding as it provides access to the kernel with complete access to sensitive and critical operating system components.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment. 

If any user accounts, or groups, (to include administrators) are granted the “Debug programs” right, then this is a finding.  

If Administrators require this right for troubleshooting or application issues, it should be assigned on a 
temporary basis as needed.

Documentable Explanation: Some applications may require this right to function such as the Windows 2003 Cluster service account. Any exception needs to be documented with the IAO.  Acceptable forms of documentation include vendor published documents and application owner confirmation.'
  desc 'fix', 'Configure the system to remove any accounts from the "Debug programs" user right.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-20665r1_chk'
  tag severity: 'high'
  tag gid: 'V-18010'
  tag rid: 'SV-29589r1_rule'
  tag gtitle: 'User Right - Debug Programs'
  tag fix_id: 'F-18585r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
