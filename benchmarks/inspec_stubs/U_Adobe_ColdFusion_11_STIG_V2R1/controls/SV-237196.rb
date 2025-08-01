control 'SV-237196' do
  title 'The ColdFusion Administrator Console must be hosted in a management sandbox.'
  desc 'ColdFusion consists of the Administrator Console and hosted applications.  By separating the Administrator Console from hosted applications, the user must authenticate as a privileged user to the Administrator Console before being presented with management functionality.  This prevents non-privileged users from having visibility to functions not available to the user.  By limiting visibility, a compromised non-privileged account does not offer information to the attacker to functionality and information needed to further the attack on the application server.

By hosting the Administrator Console within its own sandbox from other hosted applications, the administrative objects are protected from reuse and modification by the other hosted applications.'
  desc 'check', 'Within the Administrator Console, navigate to the "Sandbox Security" page under the "Security" menu.

If the Administrator Console is not hosted within a sandbox, this is a finding.'
  desc 'fix', 'Navigate to the "Sandbox Security" page under the "Security" menu.  Create sandbox for the Administrator Console to operate within and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40415r641681_chk'
  tag severity: 'medium'
  tag gid: 'V-237196'
  tag rid: 'SV-237196r641683_rule'
  tag stig_id: 'CF11-05-000162'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-40378r641682_fix'
  tag 'documentable'
  tag legacy: ['SV-76955', 'V-62465']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
