control 'SV-231040' do
  title 'Samsung Android must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security.

SFR ID: FAU_GEN.1.1 #8'
  desc 'check', 'Review Samsung Android device configuration settings to confirm that audit logging is enabled.

This validation procedure is performed on the management tool Administration Console only.

On the management tool, for the device audit log section, verify that "Audit log" is set to "Enable".

If on the management tool the "Audit log" is not set to "Enable", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable audit logging.

On the management tool, in the device audit log section, set "Audit log" to "Enable".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33970r592734_chk'
  tag severity: 'medium'
  tag gid: 'V-231040'
  tag rid: 'SV-231040r608683_rule'
  tag stig_id: 'KNOX-11-018400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33943r592735_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
