control 'SV-237898' do
  title 'The IBM z/VM TCP/IP DTCPARMS files must be properly configured to connect to an external security manager.'
  desc 'A comprehensive account management process such as provided by External Security Managers (ESM) which includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service. DTCPARMS setting assures that an ESM is enabled.

Account management functions include: assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts.'
  desc 'check', 'Determine location of "DTCPARMS" File for each of the following installed servers:
FTP (FTPSERVE)
IMAP (IMAP)
NFS (VMNFS)
REXEC (REXECD)

If each "DTCPARMS" file includes the following statements, this is not a finding.

:ESM_Enable.YES
:ESM_Racroute.YES (or a valid exit name)
:ESM_Validate.YES (or a valid exit name)'
  desc 'fix', 'For each of the following installed severs:

FTP (FTPSERVE)
IMAP (IMAP)
NFS (VMNFS)
REXEC (REXECD)

Configure the DTCPARMS file in the TCP/IP configuration to include the following statements:

:ESM_Enable.YES
:ESM_Racroute.YES (or a valid exit name)
:ESM_Validate.YES (or a valid exit name)'
  impact 0.7
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41108r858924_chk'
  tag severity: 'high'
  tag gid: 'V-237898'
  tag rid: 'SV-237898r858925_rule'
  tag stig_id: 'IBMZ-VM-000020'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-41067r649533_fix'
  tag 'documentable'
  tag legacy: ['SV-93549', 'V-78843']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
