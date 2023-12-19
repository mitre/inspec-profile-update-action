control 'SV-32265' do
  title 'Servers will have a host-based Intrusion Detection System.'
  desc 'A properly configured Host-based Intrusion Detection System provides another level of defense against unauthorized access to critical servers.  With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.'
  desc 'check', 'Interview the SA to determine if there is a host-based Intrusion Detection System on each server. 

Severity Override: This finding can be downgraded to a Category III, if there is an active JIDS or Firewall protecting the network. 

If the HIPS component of HBSS is installed and active on the host and the Alerts of blocked activity are being logged and monitored, this will meet the requirement of this finding. 

A HID device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the site IAO.'
  desc 'fix', 'Install a host-based Intrusion Detection System on each server.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32923r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3289'
  tag rid: 'SV-32265r1_rule'
  tag gtitle: 'Intrusion Detection System'
  tag fix_id: 'F-29051r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This finding can be downgraded to a Category III, if there is an active JIDS or Firewall protecting the network.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
