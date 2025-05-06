control 'SV-255157' do
  title "Samsung Android's Work profile must be configured to enable audit logging."
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events for which the system must generate an audit record.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', %q(Review the configuration to determine if the Samsung Android devices' Work profile is enabling audit logging.

This validation procedure is performed on the management tool only.

On the management tool, in the Work profile restrictions, verify that "Security logging" is set to "Enable".

If on the management tool "Security logging" is not set to "Enable", this is a finding.)
  desc 'fix', %q(Configure the Samsung Android devices' Work profile to enable audit logging.

On the management tool, in the Work profile restrictions section, set "Security logging" to "Enable".)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58770r867406_chk'
  tag severity: 'medium'
  tag gid: 'V-255157'
  tag rid: 'SV-255157r867408_rule'
  tag stig_id: 'KNOX-13-210220'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58714r867407_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
