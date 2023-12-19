control 'SV-32331' do
  title 'Access to the web content and script directories must be restricted.'
  desc 'Excessive permission for the anonymous web user account is a common fault contributing to the compromise of a web server. If this account is able to upload and execute files on the web server, the organization or owner of the server will no longer have control of the asset.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. In the Action Pane select Edit Permissions.
4. Select the Security tab.
5. Review the permissions for the accounts. If the IUSR or Everyone Account permission is greater than read, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. In the Action Pane select Edit Permissions.
4. Select the Security tab.
5. Set the permissions for the accounts IUSR and Everyone to read.'
  impact 0.7
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32737r1_chk'
  tag severity: 'high'
  tag gid: 'V-2258'
  tag rid: 'SV-32331r2_rule'
  tag stig_id: 'WG290 IIS7'
  tag gtitle: 'WG290'
  tag fix_id: 'F-29064r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
