control 'SV-29671' do
  title 'A password filter that enforces DoD requirements is not installed.'
  desc 'Password complexity software (e.g., Password Policy Enforcer) enforces a minimum mix of character types and potentially other options to create strong passwords. The following policy will be implemented: 

Passwords must contain a case-sensitive character mix of upper case letters, lower case letters, numbers, and special characters, including at least one of each.

Sites are responsible for installing password complexity software that complies with current DoD requirements.'
  desc 'check', 'Verify that password complexity software is installed and enforced that requires a case-sensitive character mix of upper case letters, lower case letters, numbers, and special characters, including at least one of each.

The enpasflt password filter is available as an option on the IASE website in the Windows Support Files area (PKI required - http://iase.disa.mil/stigs/os/windows/support_files.html).     It should be tested for the particular environment. If it does not function properly or causes issues, the site will be responsible for obtaining other password complexity software to meet the requirements.

The current available versions are:

Name – Modified Date
EnPasFltV2x86.dll – 3/21/2011
EnPasFltV2x64.dll – 3/21/2011

If another product, such as PPE, or a different version of enpasflt is used, the SA should demonstrate that it is configured to enforce the DoD requirements.

For the enpasflt password filter to function properly, verify the following:

-The appropriate version of the file will be located in %systemroot%\\system32.
-The Date Modified should be 3/21/2011.
-The “Notification Packages” value under registry key “HKLM\\System\\CurrentControlSet\\Control\\LSA” must include the file name (e.g., “EnPasFltV2x86”).

Severity Override: If no password filter is used, and the security option for “Password must meet complexity requirements” (V0001150/3.028) is set to “Enabled”, then this finding can be downgraded to a Category III, since a less strict complexity algorithm is used.

Note: If a password filter is not used, the site is still responsible for requiring full compliance with DoD policy, even though the password complexity setting does not enforce the 4-character type rule.'
  desc 'fix', 'Install password complexity software and configure it to enforce the required DoD standards of a case sensitive character mix of upper case letters, lower case letters, numbers, and special characters, including at least one of each.

If the enpasflt password filter is used:

- Copy the appropriate version to %systemroot%\\system32.
- Add the file name (e.g., “EnPasFltV2x86”) to the “Notification Packages” value under registry key “HKLM\\System\\CurrentControlSet\\Control\\LSA”.
-Restart the system.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1131'
  tag rid: 'SV-29671r1_rule'
  tag gtitle: 'Strong Password Filtering'
  tag fix_id: 'F-56r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If no password filter is used, and the security option for “Password must meet complexity requirements” (V0001150/3.028) is set to “Enabled”, then this finding can be downgraded to a Category III, since a less strict complexity algorithm is used.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1'
end
