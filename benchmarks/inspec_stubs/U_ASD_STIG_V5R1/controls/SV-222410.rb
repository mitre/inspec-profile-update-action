control 'SV-222410' do
  title 'The application must have a process, feature or function that prevents removal or disabling of emergency accounts.'
  desc 'Emergency accounts are administrator accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes.

If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account which is created for use by vendors or system maintainers.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the application documentation and interview the application administrator. Identify if emergency accounts are ever used. 

If emergency accounts are not used, this requirement is not applicable.

If emergency accounts are used, validate a procedure, process, feature or function exists that will prevent the emergency account from being deleted or disabled during a crisis situation.

Examples include but are not limited to adding a flag to the account to ensure it is not deleted during a specified emergency period or placing the account in a designated group that is monitored and controlled in accordance with the crisis.

If a process, procedure, function or feature designed to prevent emergency accounts from being  deleted or disabled during a crisis situation is not available, this is a finding.'
  desc 'fix', 'Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24080r493138_chk'
  tag severity: 'low'
  tag gid: 'V-222410'
  tag rid: 'SV-222410r508029_rule'
  tag stig_id: 'APSC-DV-000310'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24069r493139_fix'
  tag 'documentable'
  tag legacy: ['V-70173', 'SV-84795']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
