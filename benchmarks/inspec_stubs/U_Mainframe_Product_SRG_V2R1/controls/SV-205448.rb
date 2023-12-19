control 'SV-205448' do
  title 'The Mainframe Product must automatically audit account modification.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply modify an existing account. Auditing of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the modification of application user accounts and, as required, notifies administrators and/or application owners. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If the Mainframe Product does not automatically audit account modification, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically audit account modification.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5714r299577_chk'
  tag severity: 'medium'
  tag gid: 'V-205448'
  tag rid: 'SV-205448r395487_rule'
  tag stig_id: 'SRG-APP-000027-MFP-000040'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-5714r299578_fix'
  tag 'documentable'
  tag legacy: ['SV-82629', 'V-68139']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
