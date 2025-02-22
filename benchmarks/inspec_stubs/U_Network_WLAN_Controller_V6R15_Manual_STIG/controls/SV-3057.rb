control 'SV-3057' do
  title 'Authorized accounts must be assigned the least privilege level necessary to perform assigned duties.'
  desc 'By not restricting authorized accounts to their proper privilege level, access to restricted functions may be allowed before authorized personnel are trained or experienced enough to use those functions. Network disruptions or outages may occur due to mistakes made by inexperienced persons using accounts with greater privileges than necessary.'
  desc 'check', 'Review the accounts authorized for access to the network device. Determine if the accounts are assigned the lowest privilege level necessary to perform assigned duties. User accounts must be set to a specific privilege level which can be mapped to specific commands or a group of commands. Authorized accounts should have the least privilege level unless deemed necessary for assigned duties.

If it is determined that authorized accounts are assigned to greater privileges than necessary, this is a finding.'
  desc 'fix', 'Configure authorized accounts with the least privilege rule. Each user will have access to only the privileges they require to perform their assigned duties.'
  impact 0.5
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-3504r8_chk'
  tag severity: 'medium'
  tag gid: 'V-3057'
  tag rid: 'SV-3057r6_rule'
  tag stig_id: 'NET0465'
  tag gtitle: 'Accounts assigned least privileges necessary to perform duties.'
  tag fix_id: 'F-3082r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
