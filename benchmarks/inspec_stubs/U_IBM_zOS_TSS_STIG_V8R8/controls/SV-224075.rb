control 'SV-224075' do
  title 'IBM z/OS NOBUFFS in SMFPRMxx must be properly set (default is MSG).'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member in SYS1.PARMLIB.

If NOBUFFS is set to "HALT", this is not a finding.

Note: If availability is an overriding concern NOBUFFS can be set to MSG.'
  desc 'fix', 'Configure NOBUFFS to "HALT" unless availability is an overriding concern then NOBUFFS can be set to MSG.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25748r516624_chk'
  tag severity: 'medium'
  tag gid: 'V-224075'
  tag rid: 'SV-224075r561402_rule'
  tag stig_id: 'TSS0-US-000020'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-25736r516625_fix'
  tag 'documentable'
  tag legacy: ['SV-107961', 'V-98857']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
