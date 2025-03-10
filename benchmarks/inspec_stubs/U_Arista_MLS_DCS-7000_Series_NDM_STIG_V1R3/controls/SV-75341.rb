control 'SV-75341' do
  title 'The Arista Multilayer Switch must protect the audit records of nonlocal accesses to privileged accounts and the execution of privileged functions.'
  desc 'Auditing may not be reliable when performed by the network device to which the user being audited has privileged access. The privileged user may inhibit auditing or modify audit records. This control enhancement helps mitigate this risk by requiring that privileged access be further defined between audit-related privileges and other privileges, thus limiting the users with audit-related privileges. Reducing the risk of audit compromises by privileged users can also be achieved by performing audit activity on a separate information system or by using storage media that cannot be modified (e.g., write-once recording devices).'
  desc 'check', 'Review the network device account configuration files to determine if the privileged functions to access and modify audit settings and files are restricted to authorized security personnel. Review locations of audit logs generated as a result of nonlocal accesses to privileged accounts and the execution of privileged functions. Verify there are appropriate controls and permissions to protect the audit information from unauthorized access.

If the audit records that are generated upon nonlocal access to privileged accounts or upon the execution of privileged functions are not protected, this is a finding.

Verify remote logging is enabled via the "Show Logging" command.

Verify that individual accounts do not have access to logging functionality by executing the "show user-account" command and validating that only intended users are assigned to roles that permit access to logging functions. To verify what permissions are allowed by each role, execute the "show roles" command.'
  desc 'fix', 'Configure the system to protect the audit records of nonlocal accesses to privileged accounts and the execution of privileged functions.

Enable remote logging with:

config
logging host a.b.c.d
logging trap informational

To assign a user to a role, use the command:

username [name] role [role name]

To deny access to logging functions via RBAC:

role [name]
deny command logging [all]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60883'
  tag rid: 'SV-75341r1_rule'
  tag stig_id: 'AMLS-NM-000420'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-66595r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
