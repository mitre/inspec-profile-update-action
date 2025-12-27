control 'SV-230999' do
  title 'Samsung Android Work Environment must be configured to enable audit logging.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. 

SFR ID: FAU_GEN.1.1 #8'
  desc 'check', 'Review Samsung Android device configuration settings to confirm that audit logging is enabled.

This validation procedure is performed on the management tool Administration Console only.

On the management tool, in the Work Environment restrictions section, verify that "Security logging" is set to "Enable".

If on the management tool "Security logging" is not set to "Enable", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable audit logging.

On the management tool, in the Work Environment restrictions section, set "Security logging" to "Enable".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33929r592489_chk'
  tag severity: 'medium'
  tag gid: 'V-230999'
  tag rid: 'SV-230999r607691_rule'
  tag stig_id: 'KNOX-11-018300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33902r592490_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
