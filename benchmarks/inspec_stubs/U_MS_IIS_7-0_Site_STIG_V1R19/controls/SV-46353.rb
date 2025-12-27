control 'SV-46353' do
  title 'Access to the web-site log files must be restricted.'
  desc "A major tool in exploring the web-site use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. Failure to protect log files could enable an attacker to modify the log file data or falsify events to mask an attacker's activity."
  desc 'check', 'Follow the procedures below for each site under review:
1. Open the IIS Manager.
2. Click the site name.
3. Click the Logging icon.
4. Beside Directory, Click Browse.
5. Right-click the log file name to review and click Properties.
6. Click the Security tab; ensure only authorized groups are listed, if others are listed, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name.
3. Click the Logging icon.
4. Beside Directory, Click Browse.
5. Right-click the log file name to review and click Properties.
6. Click the Security tab.
7. Set the log file permissions for the appropriate group.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32797r5_chk'
  tag severity: 'medium'
  tag gid: 'V-13689'
  tag rid: 'SV-46353r5_rule'
  tag stig_id: 'WG255 IIS7'
  tag gtitle: 'WG255'
  tag fix_id: 'F-28988r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
