control 'SV-254244' do
  title 'Windows Server 2022 shared user accounts must not be permitted.'
  desc 'Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate identification and authentication. There is no way to provide for nonrepudiation or individual accountability for system access and resource usage.'
  desc 'check', 'Determine whether any shared accounts exist. If no shared accounts exist, this is NA.

Shared accounts, such as required by an application, may be approved by the organization. This must be documented with the Information System Security Officer (ISSO). Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.

If unapproved shared accounts exist, this is a finding.'
  desc 'fix', 'Remove unapproved shared accounts from the system.

Document required shared accounts with the ISSO. Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57729r848546_chk'
  tag severity: 'medium'
  tag gid: 'V-254244'
  tag rid: 'SV-254244r848548_rule'
  tag stig_id: 'WN22-00-000070'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-57680r848547_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
