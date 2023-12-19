control 'SV-223964' do
  title 'CA-TSS MSCA ACID password changes must be documented in the change log.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'From ISPF Command Shell enter: 
Exec the CA-TSS TSSAUDIT Utility using CHANGES Control Statement.
Note: If running Quest NC-Pass, validate that the MSCA ACID has the FACILITY of NCPASS and SECURID resource in the ABSTRACT resource class.

If the MSCA password changes are documented in the change log, this is not a finding.'
  desc 'fix', 'Ensure that the MSCA password changes are documented with comments in the TSS Recovery file. The TSS Recovery file will be of sufficient size to ensure that the change is documented.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25637r516291_chk'
  tag severity: 'medium'
  tag gid: 'V-223964'
  tag rid: 'SV-223964r856101_rule'
  tag stig_id: 'TSS0-ES-000910'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-25625r516292_fix'
  tag 'documentable'
  tag legacy: ['V-98635', 'SV-107739']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
