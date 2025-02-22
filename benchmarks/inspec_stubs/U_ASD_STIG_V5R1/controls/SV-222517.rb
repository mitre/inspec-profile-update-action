control 'SV-222517' do
  title 'The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'If the application is not a configuration management or similar type of application designed to manage system processes and configurations, this requirement is not applicable.

Review the application documentation and interview the application administrator to identify if application whitelisting specifying which applications or application subcomponents are allowed to execute is in use.

Check for the existence of policy settings or policy files that can be configured to restrict application execution. Have the application administrator demonstrate how the program execution is restricted. Look for a deny-all, permit-by-exception policy of restriction.

Some methods for restricting execution include but are not limited to the use of custom capabilities built into the application or leveraging of Windows Group Policy, AppLocker, Software Restriction Policies, Java Security Manager or Role-Based Access Controls (RBAC).

If application whitelisting is not utilized or does not follow a deny-all, permit-by-exception (whitelist) policy, this is a finding.'
  desc 'fix', 'Configure the application to utilize a deny-all, permit-by-exception policy when allowing the execution of authorized software.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24187r493459_chk'
  tag severity: 'medium'
  tag gid: 'V-222517'
  tag rid: 'SV-222517r508029_rule'
  tag stig_id: 'APSC-DV-001490'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-24176r493460_fix'
  tag 'documentable'
  tag legacy: ['V-69517', 'SV-84139']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
