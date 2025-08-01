control 'SV-239846' do
  title 'The vRealize Automation application must be configured to a 15 minute of less session timeout.'
  desc 'If communications sessions remain open for extended periods of time even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the device or networks to which it is attached. Terminating sessions after a logout event or after a certain period of inactivity is a method for mitigating the risk of this vulnerability. When a user management session becomes idle, or when a user logs out of the management interface, the application server must terminate the session.'
  desc 'check', 'Verify that the session timeout is set to an organization-defined time with the following steps:

1. Log on to the admin UI as the administrator.
2. Navigate to "Global Settings".
3. Review the session timeout value in minutes.

If the session timeout setting is not set to 15 minutes or less, this is a finding.'
  desc 'fix', 'To edit the session timeout, use the following steps:

1. Log on to the admin UI as the administrator.
2. Navigate to "Global Settings".
3. Select "Edit Global Settings", edit the "Session Timeout:" setting, and then select "OK".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Application'
  tag check_id: 'C-43079r664452_chk'
  tag severity: 'medium'
  tag gid: 'V-239846'
  tag rid: 'SV-239846r879637_rule'
  tag stig_id: 'VRAU-AP-000295'
  tag gtitle: 'SRG-APP-000220-AS-000148'
  tag fix_id: 'F-43038r664453_fix'
  tag 'documentable'
  tag legacy: ['SV-99777', 'V-89127']
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']
end
