control 'SV-225433' do
  title 'Servers must have a host-based Intrusion Detection System.'
  desc 'A properly configured host-based Intrusion Detection System provides another level of defense against unauthorized access to critical servers.  With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.'
  desc 'check', 'Determine whether there is a host-based Intrusion Detection System on each server. 

If the HIPS component of ESS is installed and active on the host and the Alerts of blocked activity are being logged and monitored, this will meet the requirement of this finding. 

A HID device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the site ISSO.

If a host-based Intrusion Detection System is not installed on the system, this is a finding.'
  desc 'fix', 'Install a host-based Intrusion Detection System on each server.

Severity Override Guidance: This finding can be downgraded to a CAT III if there is an active HIDS or firewall protecting the network.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27132r793242_chk'
  tag severity: 'medium'
  tag gid: 'V-225433'
  tag rid: 'SV-225433r793244_rule'
  tag stig_id: 'WN12-GE-000022'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27120r793243_fix'
  tag 'documentable'
  tag legacy: ['SV-52105', 'V-3289']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
