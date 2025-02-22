control 'SV-223697' do
  title 'IBM z/OS SYS1.PARMLIB must be properly protected.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

SYS1.PARMLIB contains the parameters that control audit configuration. Unauthorized access could result in the compromise of the operating system environment, ACP, and customer data.

"
  desc 'check', 'Execute a dataset list of access to SYS1.PARMLIB.

If the ESM data set rules for SYS1.PARMLIB allow inappropriate (e.g., global READ) access, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ, WRITE or greater access to only systems programming personnel, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ and UPDATE access to only domain level security administrators, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ access to only system Level Started Tasks, authorized Data Center personnel, and auditors, this is a finding.

If data set rules for SYS1.PARMLIB do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged, this is a finding.'
  desc 'fix', 'Configure access rules for SYS1.PARMLIB as follows:

Systems programming personnel will be authorized to WRITE or greater the SYS1.PARMLIB concatenation.

Domain level security administrators can be authorized to update the SYS1.PARMLIB concatenation.

System Level Started Tasks, authorized Data Center personnel, and auditor can be authorized read access by the ISSO.

All WRITE or greater access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25370r514779_chk'
  tag severity: 'high'
  tag gid: 'V-223697'
  tag rid: 'SV-223697r604139_rule'
  tag stig_id: 'RACF-ES-000500'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-25358r514780_fix'
  tag satisfies: ['SRG-OS-000063-GPOS-00032', 'SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000362-GPOS-00149']
  tag 'documentable'
  tag legacy: ['V-98101', 'SV-107205']
  tag cci: ['CCI-000213', 'CCI-000171', 'CCI-001914', 'CCI-001812', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'AU-12 b', 'AU-12 (3)', 'CM-11 (2)', 'CM-5 (6)', 'AC-6 (10)']
end
