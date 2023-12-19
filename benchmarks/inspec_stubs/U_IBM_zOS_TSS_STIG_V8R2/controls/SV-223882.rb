control 'SV-223882' do
  title 'IBM z/OS SYS1.PARMLIB must be properly protected.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

"
  desc 'check', 'Execute a data set list of access to SYS1.PARMLIB.

If the ESM data set rules for SYS1.PARMLIB allow inappropriate (e.g., global READ) access, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ, WRITE or greater access to only systems programming personnel, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ and UPDATE access to only domain level security administrators, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ access to only system Level Started Tasks, authorized Data Center personnel, and auditors, this is a finding.

If data set rules for SYS1.PARMLIB do not specify that all (i.e., failures and successes) WRITE or greater access will be logged, this is a finding.'
  desc 'fix', 'Ensure the accesses are being logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25555r516045_chk'
  tag severity: 'high'
  tag gid: 'V-223882'
  tag rid: 'SV-223882r561402_rule'
  tag stig_id: 'TSS0-ES-000090'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-25543r516046_fix'
  tag satisfies: ['SRG-OS-000063-GPOS-00032', 'SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000362-GPOS-00149', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98471', 'SV-107575']
  tag cci: ['CCI-001499', 'CCI-001812', 'CCI-001914', 'CCI-000171', 'CCI-000213', 'CCI-002235']
  tag nist: ['CM-5 (6)', 'CM-11 (2)', 'AU-12 (3)', 'AU-12 b', 'AC-3', 'AC-6 (10)']
end
