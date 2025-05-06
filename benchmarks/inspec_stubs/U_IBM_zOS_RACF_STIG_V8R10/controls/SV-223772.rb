control 'SV-223772' do
  title 'IBM z/OS BUFUSEWARN in the SMFPRMxx must be properly set.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member in SYS1.PARMLIB.

If BUFUSEWARN is set for "75" (75%) or less, this is not a finding.'
  desc 'fix', 'Configure the BUFUSEWARN statement in SMFPRMxx to "75" (75%) or less.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25445r515004_chk'
  tag severity: 'medium'
  tag gid: 'V-223772'
  tag rid: 'SV-223772r877389_rule'
  tag stig_id: 'RACF-OS-000160'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-25433r515005_fix'
  tag satisfies: ['SRG-OS-000343-GPOS-00134', 'SRG-OS-000344-GPOS-00135', 'SRG-OS-000046-GPOS-00022']
  tag 'documentable'
  tag legacy: ['V-98251', 'SV-107355']
  tag cci: ['CCI-000139', 'CCI-001855', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (1)', 'AU-5 (2)']
end
