control 'SV-226253' do
  title 'Servers must have a host-based Intrusion Detection System.'
  desc 'A properly configured host-based Intrusion Detection System provides another level of defense against unauthorized access to critical servers.  With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.'
  desc 'check', 'Determine whether there is a host-based Intrusion Detection System on each server. 

If the HIPS component of ESS is installed and active on the host and the Alerts of blocked activity are being logged and monitored, this will meet the requirement of this finding. 

A HID device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the site ISSO.

If a host-based Intrusion Detection System is not installed on the system, this is a finding.'
  desc 'fix', 'Install a host-based Intrusion Detection System on each server.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27955r794617_chk'
  tag severity: 'medium'
  tag gid: 'V-226253'
  tag rid: 'SV-226253r794618_rule'
  tag stig_id: 'WN12-GE-000022'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27943r476604_fix'
  tag 'documentable'
  tag legacy: ['SV-52105', 'V-3289']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
