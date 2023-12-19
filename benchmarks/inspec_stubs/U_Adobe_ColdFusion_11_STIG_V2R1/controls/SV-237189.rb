control 'SV-237189' do
  title 'ColdFusion must authenticate users individually.'
  desc 'To assure individual accountability and prevent unauthorized access, application server users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals.  Use of a group authenticator alone does not uniquely identify individual users.

ColdFusion is installed with a Root Administrator  Account.  This account is configured during the installation phase.  This account should only be used for initial setup before user accounts are created and should not be used for day-to-day operations.  When used as a group account, accountability, along with least privileges for the users, is lost.'
  desc 'check', 'Within the Administrator Console, navigate to the "User Manager" page under the "Security" menu.

If there are no defined users, this is a finding.'
  desc 'fix', 'Navigate to the "User Manager" page under the "Security" menu.  Create users that need access to the Administrator Console providing only the roles necessary to perform each job function.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40408r641660_chk'
  tag severity: 'medium'
  tag gid: 'V-237189'
  tag rid: 'SV-237189r641662_rule'
  tag stig_id: 'CF11-04-000128'
  tag gtitle: 'SRG-APP-000153-AS-000104'
  tag fix_id: 'F-40371r641661_fix'
  tag 'documentable'
  tag legacy: ['SV-76941', 'V-62451']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
