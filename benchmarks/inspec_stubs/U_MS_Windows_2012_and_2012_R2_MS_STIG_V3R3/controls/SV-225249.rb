control 'SV-225249' do
  title 'Shared user accounts must not be permitted on the system.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide adequate identification and authentication.  There is no way to provide for nonrepudiation or individual accountability for system access and resource usage.'
  desc 'check', 'Determine whether any shared accounts exist. If no shared accounts exist, this is NA.

Shared accounts, such as required by an application, may be approved by the organization.  This must be documented with the ISSO. Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.

If unapproved shared accounts exist, this is a finding.'
  desc 'fix', 'Remove unapproved shared accounts from the system.

Document required shared accounts with the ISSO. Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26948r471089_chk'
  tag severity: 'medium'
  tag gid: 'V-225249'
  tag rid: 'SV-225249r569185_rule'
  tag stig_id: 'WN12-00-000012'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-26936r471090_fix'
  tag 'documentable'
  tag legacy: ['V-1072', 'SV-52839']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
