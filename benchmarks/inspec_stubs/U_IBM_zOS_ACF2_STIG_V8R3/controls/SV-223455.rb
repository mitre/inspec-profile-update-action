control 'SV-223455' do
  title 'CA-ACF2 must limit access to data sets used to back up and/or dump SMF collection files to appropriate users and/or batch jobs that perform SMF dump processing.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Obtain the procedures and collection specifics for SMF data sets and backup.

If the ESM data set rules for the SMF dump/backup files do not restrict WRITE or greater access to authorized site personnel (e.g., systems programmers and batch jobs that perform SMF processing), this is a finding.

If the ESM dataset rules for the SMF dump/backup files do not restrict update access as documented in the site security plan, this is a finding.

If the ESM data set rules for the SMF dump/backup files do not restrict READ access to auditors and others approved by the ISSM, this is a finding.

If the ESM data set rules for the SMF dump/backup files do not specify that all (i.e., failures and successes) WRITE or greater access will be logged, this is a finding.'
  desc 'fix', 'Define WRITE or greater access to data sets used to back up and/or dump SMF collection files to be limited to system programmers and/or batch jobs that perform SMF dump processing. Ensure that all data set access is logged.

Define data set rules for the SMF dump/backup files to restrict UPDATE access to others approved by the ISSM.

Define READ Access to data sets used to back up and/or dumpSMF collection files to be limited to auditors and others approved by the ISSM.

Ensure that all WRITE or greater access authority to SMF history files will be logged using the ESM’s facilities.

Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect data sets used to back up and/or dump SMF Collection Files.

In z/OS systems, SMF data is the ultimate record of system activity. Therefore, SMF data is of the most sensitive and critical nature. While the length of time for which SMF data will be retained is not specifically regulated, it is imperative that the information is available for the longest possible time period in case of subsequent investigations. The statute of limitations varies according to the nature of a crime. It may vary by jurisdiction, and some crimes are not subject to a statute of limitations. Apply the following guidelines to the retention of SMF data for all DOD systems:

(a) Retain at least two (2) copies of the SMF data.
(b) Maintain SMF data for a minimum of one year.
(c) All WRITE or greater access authority to SMF history files will be logged using the ACP’s facilities. Only systems programming personnel and batch jobs that perform SMF functions will be authorized to update the SMF files.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25128r504497_chk'
  tag severity: 'medium'
  tag gid: 'V-223455'
  tag rid: 'SV-223455r533198_rule'
  tag stig_id: 'ACF2-ES-000340'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25116r504498_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000206-GPOS-00084', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-97607', 'SV-106711']
  tag cci: ['CCI-000213', 'CCI-001314', 'CCI-002235']
  tag nist: ['AC-3', 'SI-11 b', 'AC-6 (10)']
end
