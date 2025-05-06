control 'SV-29994' do
  title 'Sign-on to the ESCD Application Console must be restricted to only authorized personnel.'
  desc 'The ESCD Application Console is used to add, change, and delete port configurations and to dynamically switch paths between devices. Access to the ESCD Application Console is restricted to three classes of personnel: Administrators, service representatives and operators. The administrator sign-on controls passwords at all levels, the service representative sign-on allows access to maintenance procedures, and the operator sign-on allows for configuration changes and use of the Director utilities. Unrestricted use by unauthorized personnel could impact the integrity of the environment. This would result in a loss of secure operations and impact data operating environment integrity.  NOTE: Many newer installations no longer support the ESCD Application Console.  For installations not supporting the ESCD Application Console, this check is not applicable.'
  desc 'check', 'If the ESCD Application Console is present, have the ESCON System Administrator verify that sign-on access to the ESCD Application Console is restricted to authorized personnel by signing on without a valid userid and password, otherwise this check is not applicable.

If the ESCD Application Console sign-on access is not restricted, this is a finding.'
  desc 'fix', "Review access authorization to ESCD Application Console and ensure that all personnel are restricted to authorized levels of access.

The ESCD Application Console and its associated ESCON Director can be secured using passwords. Three levels of password controls have been established. Each password level controls different ESCD Application Console functions. Prior to making any changes or accessing utilities or maintenance procedures, a user is required to enter a password. A password administrator must use the ESCD Application Console to enable an authorized user access. Following are the three levels of password authority:
Administration (Level 1)
Restrict to systems programming personnel who serve as administrators. A Level 1 password allows the user to display, add, change, and delete passwords of all of the ESCON Director Level 1, Level 2, and Level 3 users. It does not allow the administrator to access maintenance procedures or utilities or to change connectivity attributes.
Maintenance (Level 2)
Restrict to service representatives who perform maintenance procedures. Level 2 users cannot view other users' passwords, change passwords, change connectivity attributes, or access utilities.
Operations (Level 3)
Restrict to system administrators responsible for changing connectivity attributes and accessing certain utilities. Level 3 users cannot view other users' passwords, change passwords, or perform maintenance procedures."
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-2769r4_chk'
  tag severity: 'medium'
  tag gid: 'V-24342'
  tag rid: 'SV-29994r3_rule'
  tag stig_id: 'HLESC020'
  tag gtitle: 'HLESC020'
  tag fix_id: 'F-2355r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002227', 'CCI-002235']
  tag nist: ['AC-6 (5)', 'AC-6 (10)']
end
