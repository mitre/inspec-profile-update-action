control 'SV-202088' do
  title 'The network device must automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information Assurance Officers (IAO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Determine if the network device automatically audits account enabling actions.  This requirement may be verified by demonstration, configuration review, or validated test results. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. If account enabling actions are not automatically audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2214r381866_chk'
  tag severity: 'medium'
  tag gid: 'V-202088'
  tag rid: 'SV-202088r399652_rule'
  tag stig_id: 'SRG-APP-000319-NDM-000283'
  tag gtitle: 'SRG-APP-000319'
  tag fix_id: 'F-2215r381867_fix'
  tag 'documentable'
  tag legacy: ['SV-69449', 'V-55203']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
