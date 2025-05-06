control 'SV-233126' do
  title 'The container platform must never automatically remove or disable emergency accounts.'
  desc 'Emergency accounts are administrator accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account that is created for use by vendors or system maintainers.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the container platform to determine if emergency accounts are automatically removed or disabled. 

If emergency accounts are automatically removed or disabled, this is a finding.'
  desc 'fix', 'Configure the container platform to never remove or disable emergency accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36062r599014_chk'
  tag severity: 'medium'
  tag gid: 'V-233126'
  tag rid: 'SV-233126r599509_rule'
  tag stig_id: 'SRG-APP-000234-CTR-000590'
  tag gtitle: 'SRG-APP-000234'
  tag fix_id: 'F-36030r599015_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
