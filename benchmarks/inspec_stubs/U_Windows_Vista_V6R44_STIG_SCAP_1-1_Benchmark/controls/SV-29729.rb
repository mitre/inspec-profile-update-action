control 'SV-29729' do
  title 'The system must generate an audit event when the audit log reaches a percentage of full threshold.'
  desc 'Audit records may be lost if the security log becomes full.  When the audit log reaches a given percent full, an audit event is written to the security log.  An event is recorded as a success audit under the category of System.  This option may be especially useful if the audit logs are set to be cleared manually.'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, or automatically archive full logs, this is NA.  This must be documented with the ISSO.
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90%" or less.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-4108'
  tag rid: 'SV-29729r2_rule'
  tag gtitle: 'Audit Log Warning Level'
  tag fix_id: 'F-63863r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECRR-1'
  tag cci: ['CCI-000139', 'CCI-001855', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (1)', 'AU-5 (2)']
end
