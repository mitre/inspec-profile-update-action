control 'SV-237186' do
  title 'Unsupported versions of ColdFusion must be uninstalled or upgraded'
  desc 'Without the current update installed, the product may be unstable or become a target for an attacker who can take advantage of a known exploit. ColdFusion 11 is no longer supported by the vendor. Unsupported versions of ColdFusion must be uninstalled or upgraded as part of an approved application management process.'
  desc 'check', 'Open the ColdFusion Administrator Console. Check the version of ColdFusion.  If the system is running ColdFusion 11, this is a finding.'
  desc 'fix', 'Upgrade ColdFusion to a supported version or uninstall the application.  All upgrade or uninstall actions should be executed in accordance with an approved application management plan.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40405r766575_chk'
  tag severity: 'high'
  tag gid: 'V-237186'
  tag rid: 'SV-237186r766577_rule'
  tag stig_id: 'CF11-03-000117'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-40368r766576_fix'
  tag 'documentable'
  tag legacy: ['SV-76935', 'V-62445']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
