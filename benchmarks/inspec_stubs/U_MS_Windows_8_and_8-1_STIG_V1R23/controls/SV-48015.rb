control 'SV-48015' do
  title 'Shared user accounts must not be permitted on the system.'
  desc 'Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate identification and authentication. There is no way to provide for non-repudiation or individual accountability for system access and resource usage. Documentation must include a list of personnel that have access to each shared account.'
  desc 'check', 'Determine if any shared accounts exist.  If no shared accounts exist, this is NA.

Any shared account must be documented with the ISSO.  Documentation must include the reason for the account, who has access to this account, and how the risk of using a shared account (which provides no individual identification and accountability) is mitigated.    If such documentation does not exist, or is not current, this is a finding.
  
Note: As an example, a shared account may be permitted for a help desk or a site security personnel machine, if that machine is standalone and has no access to the network.'
  desc 'fix', 'Create or update shared accounts documentation that minimally contains the name of the shared account(s), the system(s) on which the accounts exist, and the individuals who have access to the accounts.   Remove any shared accounts that do not meet the requirements.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44753r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1072'
  tag rid: 'SV-48015r2_rule'
  tag stig_id: 'WN08-00-000002'
  tag gtitle: 'Shared User Accounts'
  tag fix_id: 'F-41153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
