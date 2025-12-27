control 'SV-93595' do
  title 'The IBM z/VM TCP/IP ANONYMOU statement must not be coded in FTP configuration.'
  desc 'Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.'
  desc 'check', 'If there is no FTP Server active, this is not applicable.

Examine the “DTCPARMS” file for each active FTP server.

If there is “:ANONYMOUS” or “:ANONYMOU” statement, this is a finding.

Examine the “SRVRFTP” command.

If “ANONYMOU” is coded, this is a finding.'
  desc 'fix', 'Ensure the “:ANONYMOUS” or “:ANONYMOU” statement is not coded in the “DTCPARMS” or “SRVRFTP” command.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78475r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78889'
  tag rid: 'SV-93595r1_rule'
  tag stig_id: 'IBMZ-VM-000680'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-85639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
