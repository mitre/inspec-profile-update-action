control 'SV-223549' do
  title 'IBM z/OS BUFUSEWARN in the SMFPRMxx must be properly set.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member in SYS1.PARMLIB.

If BUFUSEWARN is set for 75 (75%) or less this is not a finding.'
  desc 'fix', 'Configure the BUFUSEWARN statement in SMFPRMxx to 75 (75%) or less.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25222r504686_chk'
  tag severity: 'medium'
  tag gid: 'V-223549'
  tag rid: 'SV-223549r533198_rule'
  tag stig_id: 'ACF2-OS-000130'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-25210r504687_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000343-GPOS-00134', 'SRG-OS-000344-GPOS-00135']
  tag 'documentable'
  tag legacy: ['V-97803', 'SV-106907']
  tag cci: ['CCI-001855', 'CCI-001858', 'CCI-000139']
  tag nist: ['AU-5 (1)', 'AU-5 (2)', 'AU-5 a']
end
