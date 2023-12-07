control 'SV-205851' do
  title 'Windows Server 2019 must have a host-based intrusion detection or prevention system.'
  desc 'A properly configured Host-based Intrusion Detection System (HIDS) or Host-based Intrusion Prevention System (HIPS) provides another level of defense against unauthorized access to critical servers. With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.'
  desc 'check', 'Determine whether there is a HIDS or HIPS on each server. 

If the HIPS component of ESS is installed and active on the host and the alerts of blocked activity are being logged and monitored, this meets the requirement. 

A HIDS device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the ISSO.

If a HIDS is not installed on the system, this is a finding.'
  desc 'fix', 'Install a HIDS or HIPS on each server.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6116r793213_chk'
  tag severity: 'medium'
  tag gid: 'V-205851'
  tag rid: 'SV-205851r793214_rule'
  tag stig_id: 'WN19-00-000120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6116r355916_fix'
  tag 'documentable'
  tag legacy: ['SV-103307', 'V-93219']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
