control 'SV-29622' do
  title 'Shared user accounts are permitted on the system.'
  desc 'Shared accounts do not provide individual accountability for system access and resource usage.'
  desc 'check', 'Interview the SA to determine if any shared accounts exist.  

Any shared account must be documented with the IAO.  Documentation should include the reason for the account, who has access to this account, and how the risk of using a shared account (which provides no individual identification and accountability) is mitigated.    
  
Note: As an example, a shared account may be permitted for a help desk or a site security personnel machine, if that machine is stand-alone and has no access to the network.'
  desc 'fix', 'Remove any shared accounts that do not meet the exception requirements listed.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-7885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1072'
  tag rid: 'SV-29622r1_rule'
  tag gtitle: 'Shared User Accounts'
  tag fix_id: 'F-33r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
