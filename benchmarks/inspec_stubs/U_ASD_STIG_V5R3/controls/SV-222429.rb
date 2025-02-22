control 'SV-222429' do
  title 'The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Identify the application user account(s) that the application uses to run. These accounts include the application processes (defined by Control Panel Services (Windows) or ps –ef (UNIX)) or for an n-tier application, the account that connects from one service (such as a web server) to another (such as a database server).

Determine the OS user groups in which each account is a member.

List the user rights assigned to these users and groups and evaluate whether any of them are unnecessary.

If the OS rights exceed application operational requirements, this is a finding.

If the application user account is a member of the Administrators group (Windows) or has a User Identification (UID) of 0 (i.e., is equivalent to root in UNIX), this is a finding.

Search the file system to determine if the application user or groups have ownership or permissions to any files or directories.

Review the list of files and identify any that are outside the scope of the application.

If there are such files outside the scope of the application, this is a finding.

Check ownership and permissions; identify permissions beyond the minimum necessary to support the application.

If there are instances of unnecessary ownership or permissions, this is a finding.

The finding details should note the full path of the file(s) and the associated issue (i.e., outside scope, permissions improperly granted to user X, etc.).'
  desc 'fix', 'Modify the application to limit access and prevent the disabling or circumvention of security safeguards.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24099r493195_chk'
  tag severity: 'medium'
  tag gid: 'V-222429'
  tag rid: 'SV-222429r879717_rule'
  tag stig_id: 'APSC-DV-000500'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-24088r493196_fix'
  tag 'documentable'
  tag legacy: ['SV-83959', 'V-69337']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
