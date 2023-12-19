control 'SV-205446' do
  title 'The Mainframe Product must automatically disable accounts after 35 days of account inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Applications need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are security administrator accounts used by system programmers when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If the Mainframe Product automatically disables accounts after 35 days of inactivity, this is not a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically disable accounts after 35 days of account inactivity.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5712r299571_chk'
  tag severity: 'medium'
  tag gid: 'V-205446'
  tag rid: 'SV-205446r395481_rule'
  tag stig_id: 'SRG-APP-000025-MFP-000038'
  tag gtitle: 'SRG-APP-000025'
  tag fix_id: 'F-5712r299572_fix'
  tag 'documentable'
  tag legacy: ['SV-82625', 'V-68135']
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
