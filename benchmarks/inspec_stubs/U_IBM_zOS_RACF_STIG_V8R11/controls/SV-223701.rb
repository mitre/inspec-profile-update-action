control 'SV-223701' do
  title 'IBM z/OS must limit access for SMF collection files (i.e., SYS1.MANx) to appropriate users and/or batch jobs that perform SMF dump processing.'
  desc 'SMF data collection is the system activity journaling facility of the z/OS system. Unauthorized access could result in the compromise of logging and recording of the operating system environment, ESM, and customer data.

Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Refer to the SMFPRMxx member in SYS1.PARMLIB. Determine the SMF and/or Logstream dataset name.

If the following statements are true, this is not a finding.

The ESM data set rules for the SMF data collection files (e.g., SYS1.MAN* or IFASMF.SYS1.*) restrict WRITE or greater access to only z/OS systems programming personnel.

The ESM data set rules for the SMF data collection files (e.g., SYS1.MAN* or IFASMF.SYS1.*) restrict UPDATE access to z/OS systems programming personnel, and/or batch jobs that perform SMF dump processing and others approved by ISSM.

The ESM data set rules for the SMF data collection files (e.g., SYS1.MAN* or IFASMF.SYS1.*) restrict READ access to auditors and others approved by the ISSM.

The ESM data set rules for SMF data collection files (e.g., SYS1.MAN* or IFASMF.SYS1.*) specify that all (i.e., failures and successes) UPDATE and/or ALTER access are logged.'
  desc 'fix', 'Configure WRITE and above access to SMF collection files to be limited to only systems programming staff and and/or batch jobs that perform SMF dump processing, access can be granted to others as determined by ISSM.

Configure READ access to be limited to auditors. READ access may be granted to others as determined by the ISSM.

Access to other users specified must be documented in a security plan.

Ensure the accesses are being logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25374r514791_chk'
  tag severity: 'medium'
  tag gid: 'V-223701'
  tag rid: 'SV-223701r853604_rule'
  tag stig_id: 'RACF-ES-000540'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-25362r514792_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000256-GPOS-00097', 'CCI-001494', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099', 'SRG-OS-000080-GPOS-00048', 'SRG-OS-000206-GPOS-00084', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98109', 'SV-107213']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000213', 'CCI-001314', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-002235']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AC-3', 'SI-11 b', 'AU-9 a', 'AU-9', 'AU-9', 'AC-6 (10)']
end
