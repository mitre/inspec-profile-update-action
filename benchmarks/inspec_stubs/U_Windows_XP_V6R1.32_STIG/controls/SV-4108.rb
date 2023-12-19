control 'SV-4108' do
  title 'The system does not generate an audit event when the audit log reaches a percent full threshold.'
  desc 'When the audit log reaches a given percent full, an audit event is written to the security log. The event ID is 523 and is recorded as a success audit under the category of System. This option may be especially useful if the audit logs are set to be cleared manually. A recommended setting would be 90 percent.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning” is not set to “90” or less, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Eventlog\\Security\\

Value Name:  WarningLevel

Value Type:  REG_DWORD
Value:  90

Documentable Explanation: If the system is configured to write to an audit server, or is configured to automatically archive full logs this should be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning” to “90” or less.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32753r1_chk'
  tag severity: 'low'
  tag gid: 'V-4108'
  tag rid: 'SV-4108r1_rule'
  tag gtitle: 'Audit Log Warning Level'
  tag fix_id: 'F-28831r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECRR-1'
end
