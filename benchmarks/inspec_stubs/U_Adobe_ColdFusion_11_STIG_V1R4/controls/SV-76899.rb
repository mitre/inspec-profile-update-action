control 'SV-76899' do
  title 'ColdFusion must disable the In-Memory File System.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  ColdFusion offers an in-memory file system.  This feature can be used to have dynamic code execute quickly which in turns enables an application to execute quicker.  This feature can also be used by an attacker to execute dynamic code that is erased and unrecoverable on system reboot making forensic analysis impossible.'
  desc 'check', 'Ask the administrator if the in-memory file system is being used by any hosted applications.

If hosted applications are using the in-memory file system, this is not a finding.

Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If "Enable In-Memory File System" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Uncheck "Enable In-Memory File System" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63213r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62409'
  tag rid: 'SV-76899r1_rule'
  tag stig_id: 'CF11-03-000098'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68329r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
