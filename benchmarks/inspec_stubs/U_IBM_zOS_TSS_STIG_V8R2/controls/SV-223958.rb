control 'SV-223958' do
  title 'CA-TSS ACID creation must use the EXP option.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon.

Temporary passwords are typically used to allow access when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log on, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Ask the system administrator for the procedures for creating new ACIDs.

If the procedure contains the "EXP" option, this is not a finding.'
  desc 'fix', %q(Assure procedures to create New Acids include the "EXP" option.

Example:
TSS CREATE(USER02) NAME('ANDY POE')
TYPE(USER)
DEPARTMENT(PAYDEPT)
PASSWORD(INITIAL,60,EXP)
FACILITY(TSO))
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25631r516273_chk'
  tag severity: 'medium'
  tag gid: 'V-223958'
  tag rid: 'SV-223958r561402_rule'
  tag stig_id: 'TSS0-ES-000850'
  tag gtitle: 'SRG-OS-000380-GPOS-00165'
  tag fix_id: 'F-25619r516274_fix'
  tag 'documentable'
  tag legacy: ['SV-107727', 'V-98623']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
