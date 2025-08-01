control 'SV-223686' do
  title 'IBM RACF must limit access to data sets used to back up and/or dump SMF collection files to appropriate users and/or batch jobs that perform SMF dump processing.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Obtain the procedures and collection specifics for SMF datasets and backup.

If the ESM data set rules for the SMF dump/backup files do not restrict WRITE or greater to authorized DISA and site personnel (e.g., systems programmers and batch jobs that perform SMF processing), this is a finding.

If the ESM dataset rules for the SMF dump/backup files do not restrict update access as documented in the site security plan, this is a finding.

If the ESM data set rules for the SMF dump/backup files do not restrict READ access to auditors and others approved by the ISSM, this is a finding.

If the ESM data set rules for SMF dump/backup files do not specify that all (i.e., failures and successes) WRITE or greater will be logged, this is a finding.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect datasets used to backup and/or dump SMF collection files.

Configure data set rules for the SMF dump/backup files to restrict WRITE or greater access to authorized DISA and site personnel (e.g., systems programmers and batch jobs that perform SMF processing).

Configure data set rules for the SMF dump/backup files to restrict UPDATE access to others approved the ISSM.

Configure data set rules for the SMF dump/backup files to restrict READ access to authorized auditors and others approved by the ISSM.

Ensure that all WRITE or greater access authority to SMF history files will be logged using the ESM’s facilities.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25359r516745_chk'
  tag severity: 'medium'
  tag gid: 'V-223686'
  tag rid: 'SV-223686r853590_rule'
  tag stig_id: 'RACF-ES-000380'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25347r516746_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000206-GPOS-00084', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107181', 'V-98077']
  tag cci: ['CCI-000213', 'CCI-001314', 'CCI-002235']
  tag nist: ['AC-3', 'SI-11 b', 'AC-6 (10)']
end
