control 'SV-246935' do
  title 'ONTAP must have audit guarantee enabled.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. With audit guarantee enabled, all SMB operations must generate an audit event before an ACK is returned to the client and the operation completed.  If the audit event cannot be written, then the client operation is delayed or denied.'
  desc 'check', 'Use "vserver audit show -fields audit-guarantee" to see if audit guarantee is enabled.

If audit-guarantee is set to false, this is a finding.'
  desc 'fix', 'Use the command "vserver audit modify -vserver <vserver_name> -destination <audit log location> -audit-guarantee true" to set audit-guarantee to true.  

An example command for a vserver named svm01 with the audit logs at /audit_log would be "vserver audit modify -vserver svm01 -destination /audit_log -audit-guarantee true".

Use the command "vserver audit show -fields audit-guarantee" to verify the change.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50367r856966_chk'
  tag severity: 'medium'
  tag gid: 'V-246935'
  tag rid: 'SV-246935r856968_rule'
  tag stig_id: 'NAOT-AU-000003'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-50321r856967_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
