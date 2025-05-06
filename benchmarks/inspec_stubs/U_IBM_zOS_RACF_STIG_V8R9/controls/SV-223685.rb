control 'SV-223685' do
  title 'IBM RACF security data sets and/or databases must be properly protected.'
  desc 'The External Security Manager (ESM) database files contain all access control information for the operating system environment and system resources. Unauthorized access could result in the compromise of the operating system environment, ACP, and customer data.

'
  desc 'check', 'If the following accesses to the ESM security data sets and/or databases are properly restricted as detailed below, this is not a finding.

-The ESM data set rules for ESM security data sets and/or databases restrict READ access to auditors and DASD batch.
-The ESM data set rules for ESM security data sets and/or databases restrict READ and/or greater access to z/OS systems programming personnel, security personnel, and/or batch jobs that perform ESM maintenance.

All (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, ALTER, and CONTROL) for ESM security data sets and/or databases are logged.'
  desc 'fix', 'Review access authorization to critical security database files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect the ESM files.

Configure READ and/or greater access to all ESM files and/or databases are limited to system programmers and/or security personnel, and/or batch jobs that perform ESM maintenance. READ access can be given to auditors and DASD batch. All accesses to ESM files and/or databases are logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25358r514744_chk'
  tag severity: 'high'
  tag gid: 'V-223685'
  tag rid: 'SV-223685r853589_rule'
  tag stig_id: 'RACF-ES-000370'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25346r514745_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000134-GPOS-00068', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107179', 'V-98075']
  tag cci: ['CCI-000213', 'CCI-001084', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'SC-3', 'CM-5 (6)', 'AC-6 (10)']
end
