control 'SV-98857' do
  title 'The vRealize Operations server session timeout must be configured.'
  desc 'If communications sessions remain open for extended periods of time even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the device or networks to which it is attached. Terminating sessions after a logout event or after a certain period of inactivity is a method for mitigating the risk of this vulnerability. When a user management session becomes idle, or when a user logs out of the management interface, the application server must terminate the session.'
  desc 'check', 'Verify that the session timeout is set to "15" minutes with the following steps:

1. Log on to the admin UI as the administrator.
2. Navigate to "Global Settings".
3. Review the session timeout value in mins.

If the "Session Timeout:" setting is not "15" minutes, this is a finding.'
  desc 'fix', 'To edit the session timeout, use the following steps:

1. Log on to the admin UI as the administrator.
2. Navigate to "Global Settings".
3. Select "Edit Global Settings".
4. Set the "Session Timeout:" setting to "15" minutes.
5. Select "OK".'
  impact 0.5
  ref 'DPMS Target vRealize Operations Manager 6.x Application'
  tag check_id: 'C-87899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88207'
  tag rid: 'SV-98857r1_rule'
  tag stig_id: 'VROM-AP-000295'
  tag gtitle: 'SRG-APP-000220-AS-000148'
  tag fix_id: 'F-94949r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']
end
