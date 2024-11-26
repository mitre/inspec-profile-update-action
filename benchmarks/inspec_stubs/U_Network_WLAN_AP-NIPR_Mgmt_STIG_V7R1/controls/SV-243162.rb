control 'SV-243162' do
  title 'The network device must be configured to use an authentication server to authenticate users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the network device configuration to verify all management connections use an authentication server for administrative access.

If the network device is not configured to use an authentication server for management access, this is a finding.'
  desc 'fix', 'Configure authentication for all management connections using an authentication server.'
  impact 0.7
  ref 'DPMS Target Network WLAN AP-NIPR Mgmt'
  tag check_id: 'C-46437r719939_chk'
  tag severity: 'high'
  tag gid: 'V-243162'
  tag rid: 'SV-243162r719941_rule'
  tag stig_id: 'WLAN-ND-001100'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-46394r719940_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
