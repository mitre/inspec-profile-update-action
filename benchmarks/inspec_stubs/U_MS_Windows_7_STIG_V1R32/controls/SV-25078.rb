control 'SV-25078' do
  title 'The system must generate an audit event when the audit log reaches a percentage of full threshold.'
  desc 'Audit records may be lost if the security log becomes full.  When the audit log reaches a given percent full, an audit event is written to the security log.  An event is recorded as a success audit under the category of System.  This option may be especially useful if the audit logs are set to be cleared manually.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, or automatically archive full logs, this is NA.  This must be documented with the ISSO.
Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" is not set to "90%" or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE 
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security\\

Value Name:  WarningLevel

Value Type:  REG_DWORD
Value:  0x0000005a (90) (or less)'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, or automatically archive full logs, this is NA.  This must be documented with the ISSO.
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90%" or less.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-59377r1_chk'
  tag severity: 'low'
  tag gid: 'V-4108'
  tag rid: 'SV-25078r2_rule'
  tag gtitle: 'Audit Log Warning Level'
  tag fix_id: 'F-63873r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECRR-1'
  tag cci: ['CCI-000139', 'CCI-001855', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (1)', 'AU-5 (2)']
end
