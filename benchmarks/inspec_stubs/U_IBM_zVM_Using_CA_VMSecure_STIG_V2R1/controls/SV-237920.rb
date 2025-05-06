control 'SV-237920' do
  title 'The IBM z/VM TCP/IP VMSSL command operands must be configured properly.'
  desc 'VMSSL services are initiated using the VMSSL command defined in the DTCPARMS file. Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.'
  desc 'check', 'Determine and examine the “DTCPARMS” file for each SSL server pool.

If the "VMSSL" command is not included in a :PARMS tag, this is a finding.

If the “VMSSL” command is not configured as follows, this is a finding.

FIPS (Operand FIPS is equivalent to setting MODE FIPS-140-2.)

MODE FIPS-140-2 (Operand MODE FIPS-140-2 is equivalent to setting operand FIPS.)

PROTOcol TLSV1_2'
  desc 'fix', 'Configure the SSL DTCPARMS file with a :PARMS tag that includes “VMSSL” command.

Configure the “VMSSL” command to MODE FIPS-140-2, either by including the FIPS operand or by setting the “MODE” operand to FIPS-140-2.

Include the PROTOcol operands for TLSV1_2.'
  impact 0.7
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41130r649598_chk'
  tag severity: 'high'
  tag gid: 'V-237920'
  tag rid: 'SV-237920r649600_rule'
  tag stig_id: 'IBMZ-VM-000660'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-41089r649599_fix'
  tag 'documentable'
  tag legacy: ['SV-93593', 'V-78887']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
