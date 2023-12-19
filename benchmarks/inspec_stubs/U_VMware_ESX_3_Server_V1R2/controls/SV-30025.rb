control 'SV-30025' do
  title 'The system must be configured to send audit records to a remote audit server.'
  desc "Audit records contain evidence that can be used in the investigation 
of compromised systems. To prevent this evidence from compromise, it must be sent to a separate 
system continuously. Methods for sending audit records include, but are not limited to, system 
audit tools used to send logs directly to another host or through the system's syslog service to 
another host."
  desc 'check', 'Consult vendor documentation to determine the settings required for the audit system for sending audit records to a remote system or via syslog. If the system is not configured to provide this function, this is a finding.'
  desc 'fix', 'Consult vendor documentation for the settings required to configure the system to send audit records to a remote system. Implement the configuration settings.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30814r1_chk'
  tag severity: 'low'
  tag gid: 'V-24357'
  tag rid: 'SV-30025r1_rule'
  tag stig_id: 'GEN002870'
  tag gtitle: 'GEN002870'
  tag fix_id: 'F-27394r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTB-1'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
