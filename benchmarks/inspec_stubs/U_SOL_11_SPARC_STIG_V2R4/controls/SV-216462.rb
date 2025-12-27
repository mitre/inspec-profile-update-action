control 'SV-216462' do
  title 'The operating system must conduct backups of system-level information contained in the information system per organization-defined frequency to conduct backups that are consistent with recovery time and recovery point objectives.'
  desc 'Operating system backup is a critical step in maintaining data assurance and availability. 

System-level information is data generated for/by the host (such as configuration settings) and/or administrative users.

Backups shall be consistent with organizational recovery time and recovery point objectives.'
  desc 'check', 'The operations staff shall ensure that proper backups are created, tested, and archived. 

Ask the operator for documentation on the backup procedures implemented.

If the backup procedures are not documented then this is a finding.'
  desc 'fix', 'The operations staff shall install, configure, test, and verify operating system backup software.

Additionally, all backup procedures must be documented.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17698r371474_chk'
  tag severity: 'medium'
  tag gid: 'V-216462'
  tag rid: 'SV-216462r603267_rule'
  tag stig_id: 'SOL-11.1-090060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17696r371475_fix'
  tag 'documentable'
  tag legacy: ['V-47975', 'SV-60847']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
