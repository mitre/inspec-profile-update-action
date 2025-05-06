control 'SV-32378' do
  title 'The web document (home) directory must be in a separate partition from the web server’s system files.'
  desc 'The web document (home) directory is accessed by multiple anonymous users when the web server is in production.  By locating the web document (home) directory on the same partition as the web server system file the risk for unauthorized access to these protected files is increased.  Additionally, having the web document (home) directory path on the same drive as the system folders also increases the potential for a drive space exhaustion attack.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click the Advanced Settings from the "Actions" Pane.
4. Review the Physical Path.

If the Path is on the same partition as the OS, this is a finding.

Note: If the ISSO has accepted the risk of not configuring this setting due to hosted application operability issues or failures, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click the Advanced Settings from the Actions Pane.
4. Change the Physical Path to the new partition and directory location.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32768r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3333'
  tag rid: 'SV-32378r3_rule'
  tag stig_id: 'WG205 IIS7'
  tag gtitle: 'WG205'
  tag fix_id: 'F-29069r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
