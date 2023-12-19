control 'SV-238478' do
  title 'The DBMS must verify there have not been unauthorized changes to the DBMS software and information.'
  desc 'Organizations are required to employ integrity verification applications on information systems to look for evidence of information tampering, errors, and omissions. The organization is also required to employ good software engineering practices with regard to commercial off-the-shelf integrity mechanisms (e.g., parity checks, cyclical redundancy checks, and cryptographic hashes), and to use tools to automatically monitor the integrity of the information system and the applications it hosts.

The DBMS opens data files and reads configuration files at system startup, system shutdown, and during abort recovery efforts. If the DBMS does not verify the trustworthiness of these files, it is vulnerable to malicious alterations of its configuration or unauthorized replacement of data.'
  desc 'check', 'Verify the DBMS system initialization and shutdowns are configured to ensure the DBMS system and data files remain in a secure state. If the DBMS does not support this, verify third-party software or custom scripting at the OS level performs this function.  If neither the DBMS, a third-party application, nor the OS is performing integrity verification of DBMS system files, this is a finding.'
  desc 'fix', 'Utilize a DBMS, OS, or third-party product to perform file verification of DBMS system file integrity at startup and shutdown.

(Using Oracle Configuration Manager with Enterprise Manager, configured to perform this verification, is one possible way of satisfying this requirement.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41689r667606_chk'
  tag severity: 'medium'
  tag gid: 'V-238478'
  tag rid: 'SV-238478r667608_rule'
  tag stig_id: 'O112-C2-019600'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-41648r667607_fix'
  tag 'documentable'
  tag legacy: ['V-52169', 'SV-66385']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
