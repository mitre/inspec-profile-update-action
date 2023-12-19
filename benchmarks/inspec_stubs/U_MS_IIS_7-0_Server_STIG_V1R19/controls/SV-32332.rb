control 'SV-32332' do
  title 'Web server system files must conform to minimum file permission requirements.'
  desc 'This check verifies the key web server system configuration files are owned by the SA or the web administrator controlled account. These same files that control the configuration of the web server, and thus its behavior, must also be accessible by the account running the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  desc 'check', '1. Open Explorer and navigate to the inetpub directory.
2. Right-click inetpub and select Properties.
3. Click the Security tab.
4. Verify the permissions for the following users; if the permissions are less restrictive, this is a finding.

System: Full control
Administrators: Full control
TrustedInstaller: Full control
Users: Read & execute, list folder contents
Creator/Owner: Special permissions to subkeys'
  desc 'fix', '1. Open Explorer and navigate to the inetpub directory.
2. Right-click inetpub and select Properties.
3. Click the Security tab.
4. Set the following permissions:
  System: Full control
  Administrators: Full control
  TrustedInstaller: Full control
  Users: Read & execute, list folder contents
  Creator/Owner: special permissions to subkeys'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32738r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2259'
  tag rid: 'SV-32332r2_rule'
  tag stig_id: 'WG300 IIS7'
  tag gtitle: 'WG300'
  tag fix_id: 'F-29065r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
