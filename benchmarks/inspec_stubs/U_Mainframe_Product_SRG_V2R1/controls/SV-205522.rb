control 'SV-205522' do
  title 'The Mainframe Product must be configured such that emergency accounts are never automatically removed or disabled.'
  desc 'Emergency accounts are administrator accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account which is created for use by vendors or system maintainers.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If emergency accounts are configured to never be automatically removed or disabled, this is not a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to never automatically remove or disable emergency accounts.

Accounts should be configured to terminate within 72 hours or until crisis has passed.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5788r299799_chk'
  tag severity: 'medium'
  tag gid: 'V-205522'
  tag rid: 'SV-205522r397750_rule'
  tag stig_id: 'SRG-APP-000234-MFP-000037'
  tag gtitle: 'SRG-APP-000234'
  tag fix_id: 'F-5788r299800_fix'
  tag 'documentable'
  tag legacy: ['SV-82623', 'V-68133']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
