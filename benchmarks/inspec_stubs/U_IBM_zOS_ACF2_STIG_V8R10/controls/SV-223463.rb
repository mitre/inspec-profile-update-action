control 'SV-223463' do
  title 'IBM z/OS SYS1.PARMLIB must be properly protected.'
  desc "To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

"
  desc 'check', 'Execute a data set list of access to SYS1.PARMLIB.

If the ESM data set rules for SYS1.PARMLIB allow inappropriate (e.g., global READ) access.

If data set rules for SYS1.PARMLIB do not restrict READ, UPDATE, and ALTER access to only systems programming personnel, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ and UPDATE access to only domain level security administrators, this is a finding.

If data set rules for SYS1.PARMLIB do not restrict READ access to only system Level Started Tasks, authorized Data Center personnel, and auditors, this is a finding.

If data set rules for SYS1.PARMLIB do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged, this is a finding.'
  desc 'fix', 'Configure access rules for SYS1.PARMLIB as follows:
Systems programming personnel will be authorized to update and alter the SYS1.PARMLIB concatenation.
Domain level security administrators can be authorized to update the SYS1.PARMLIB concatenation.
System Level Started Tasks, authorized Data Center personnel, and auditor can be authorized read access by the ISSO.
All update and alter access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25136r504510_chk'
  tag severity: 'high'
  tag gid: 'V-223463'
  tag rid: 'SV-223463r853527_rule'
  tag stig_id: 'ACF2-ES-000440'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-25124r504511_fix'
  tag satisfies: ['SRG-OS-000063-GPOS-00032', 'SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000362-GPOS-00149']
  tag 'documentable'
  tag legacy: ['SV-106727', 'V-97623']
  tag cci: ['CCI-000171', 'CCI-000213', 'CCI-001499', 'CCI-001812', 'CCI-001914', 'CCI-002235']
  tag nist: ['AU-12 b', 'AC-3', 'CM-5 (6)', 'CM-11 (2)', 'AU-12 (3)', 'AC-6 (10)']
end
