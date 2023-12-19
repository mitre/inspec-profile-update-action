control 'SV-60215' do
  title 'The AirWatch MDM Server must terminate the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.'
  desc 'If communication’s sessions remain open for extended periods of time even when unused, there is the potential for an adversary to highjack the session and use it to gain access to the device or networks to which it is attached.  Terminating sessions after a certain period of inactivity is a method for mitigating the risk of this vulnerability.'
  desc 'check', 'Review the AirWatch MDM Server configuration to verify the system terminates network connections after an organization-defined time period of inactivity.  If communications are not terminated at the end of a session or after an organization-defined time period of inactivity, this is a finding.

To verify the session Timeout:  (1) click "Menu" on top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click  "Admin", (4) click "Console Security", click "Session Management", and (5) verify the fields under forced timeout and idle timeout are set to 15 minutes.'
  desc 'fix', 'Configure the AirWatch MDM Server to terminate network connections at the end of the session or after the organization-defined time period of inactivity.

To adjust the session Timeout:  (1) click "Menu" on top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "Admin", (4) click "Console Security", (5) click "Session Management", and (6) configure the fields under forced timeout and idle timeout to 15 minutes.  (7) Click "Save".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50109r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47343'
  tag rid: 'SV-60215r1_rule'
  tag stig_id: 'ARWA-03-000185'
  tag gtitle: 'SRG-APP-190-MDM-047-SRV'
  tag fix_id: 'F-51049r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
