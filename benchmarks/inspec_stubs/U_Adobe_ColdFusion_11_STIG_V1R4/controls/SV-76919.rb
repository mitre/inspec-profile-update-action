control 'SV-76919' do
  title 'ColdFusion must disable auto reloading of configuration files on file changes.'
  desc 'When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software and/or application server configuration can potentially have significant effects on the overall security of the system.  Allowing ColdFusion to watch for configuration file changes and reloading the new configuration gives an attacker an easy way to make modifications and have those changes become part of the executing production system quickly.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If "Check configuration files for changes every" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Uncheck "Check configuration files for changes every" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62429'
  tag rid: 'SV-76919r1_rule'
  tag stig_id: 'CF11-03-000108'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-68349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
