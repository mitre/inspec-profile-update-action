control 'SV-255128' do
  title 'Samsung Android must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events for which the system must generate an audit record.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enabling audit logging.

This validation procedure is performed on the management tool only.

On the management tool, in the device restrictions, verify that "Security logging" is set to "Enable".

If on the management tool "Security logging" is not set to "Enable", this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enable audit logging.

On the management tool, in the device restrictions section, set "Security logging" to "Enable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58741r867319_chk'
  tag severity: 'medium'
  tag gid: 'V-255128'
  tag rid: 'SV-255128r867321_rule'
  tag stig_id: 'KNOX-13-110220'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58685r867320_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
