control 'SV-237743' do
  title 'The system must verify there have not been unauthorized changes to the DBMS software and information.'
  desc 'Organizations are required to employ integrity verification applications on information systems to look for evidence of information tampering, errors, and omissions. The organization is also required to employ good software engineering practices with regard to commercial off-the-shelf integrity mechanisms (e.g., parity checks, cyclical redundancy checks, and cryptographic hashes), and to use tools to automatically monitor the integrity of the information system and the applications it hosts.

The DBMS opens data files and reads configuration files at system startup, system shutdown, and during abort recovery efforts. If the DBMS does not verify the trustworthiness of these files, it is vulnerable to malicious alterations of its configuration or unauthorized replacement of data.'
  desc 'check', 'Verify the DBMS system initialization/parameter files and software is  included in the configuration of any  third-party software or custom scripting at the OS level to perform integrity verification.

If neither a third-party application nor the OS is performing integrity verification of DBMS system files, this is a finding.'
  desc 'fix', 'Utilize the OS or a third-party product to perform file verification of DBMS system file integrity.

(Using Oracle Configuration Manager with Enterprise Manager, configured to perform this verification, is one possible way of satisfying this requirement.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40962r667259_chk'
  tag severity: 'medium'
  tag gid: 'V-237743'
  tag rid: 'SV-237743r667261_rule'
  tag stig_id: 'O121-C2-019600'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-40925r667260_fix'
  tag 'documentable'
  tag legacy: ['V-61787', 'SV-76277']
  tag cci: ['CCI-002716']
  tag nist: ['SI-7 (6)']
end
