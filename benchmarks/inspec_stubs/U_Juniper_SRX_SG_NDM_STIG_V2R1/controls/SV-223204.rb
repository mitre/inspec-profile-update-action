control 'SV-223204' do
  title 'The Juniper SRX Services Gateway must have the number of rollbacks set to 5 or more.'
  desc 'Backup of the configuration files allows recovery in case of corruption, misconfiguration, or catastrophic failure. The maximum number of rollbacks for the SRX is 50 while the default is 5 which is recommended as a best practice. Increasing this backup configuration number will result in increased disk usage and increase the number of files to manage. Organizations should not set the value to zero.'
  desc 'check', 'To view the current setting for maximum number of rollbacks enter the following command.

[edit]
show system max-configuration-rollbacks

If the number of back up configurations is not set to an organization-defined value which is 5 or more, this is a finding.'
  desc 'fix', 'To configure number of backup configurations to be stored in the configuration partition enter the following command at the configuration hierarchy.

[edit]
set system max-configuration-rollbacks <organization-defined number>'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24877r513299_chk'
  tag severity: 'low'
  tag gid: 'V-223204'
  tag rid: 'SV-223204r513301_rule'
  tag stig_id: 'JUSX-DM-000087'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-24865r513300_fix'
  tag 'documentable'
  tag legacy: ['SV-81085', 'V-66595']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
