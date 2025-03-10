control 'SV-109129' do
  title 'The Central Log Server must automatically audit account creation.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application owners exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to automatically audit account creation.

If the Central Log Server is not configured to automatically audit account creation, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to automatically audit account creation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100025'
  tag rid: 'SV-109129r1_rule'
  tag stig_id: 'SRG-APP-000026-AU-000580'
  tag gtitle: 'SRG-APP-000026-AU-000580'
  tag fix_id: 'F-105709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
