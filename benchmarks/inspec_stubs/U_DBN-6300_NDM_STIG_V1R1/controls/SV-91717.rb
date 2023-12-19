control 'SV-91717' do
  title 'Accounts for device management must be configured on the authentication server and not the network device itself, except for the account of last resort.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat.

With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Verify that the LDAP authentication server is configured correctly.

Navigate to Settings >> Initial Configuration >> Authentication.

Verify that the LDAP server entry is correct and the button for "LDAP Based Authentication" is enabled.

Verify that the "Native takes precedence" button is set to "Disabled".

If the LDAP server entry is not present and enabled, and the "Native takes precedence" button is not set to "Disabled", this is a finding.'
  desc 'fix', 'Navigate to Settings >> Initial Configuration >> Authentication.

Enter the correct LDAP server entry.

Press the button for "LDAP Based Authentication" so that it is enabled.

If necessary, press the "Disabled" button for "Native takes precedence".

Press the "Commit" button.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-77021'
  tag rid: 'SV-91717r1_rule'
  tag stig_id: 'DBNW-DM-000134'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-83717r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
