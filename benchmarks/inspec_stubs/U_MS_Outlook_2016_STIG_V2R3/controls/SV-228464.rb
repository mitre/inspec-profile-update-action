control 'SV-228464' do
  title 'Always warn on untrusted macros must be enforced.'
  desc %q(This policy setting controls the security level for macros in Outlook. If you enable this policy setting, you can choose from four options for handling macros in Outlook: - Always warn. This option corresponds to the "Warnings for all macros" option in the "Macro Security" section of the Outlook Trust Center. Outlook disables all macros that are not opened from a trusted location, even if the macros are signed by a trusted publisher. For each disabled macro, Outlook displays a security alert dialog box with information about the macro and its digital signature (if present), and allows users to enable the macro or leave it disabled. - Never warn, disable all. This option corresponds to the "No warnings and disable all macros" option in the Trust Center. Outlook disables all macros that are not opened from trusted locations, and does not notify users. - Warning for signed, disable unsigned. This option corresponds to the "Warnings for signed macros; all unsigned macros are disabled" option in the Trust Center. Outlook handles macros as follows: --If a macro is digitally signed by a trusted publisher, the macro can run if the user has already trusted the publisher. --If a macro has a valid signature from a publisher that the user has not trusted, the security alert dialog box for the macro lets the user choose whether to enable the macro for the current session, disable the macro for the current session, or to add the publisher to the Trusted Publishers list so that it will run without prompting the user in the future. --If a macro does not have a valid signature, Outlook disables it without prompting the user, unless it is opened from a trusted location. This option is the default configuration in Outlook. - No security check. This option corresponds to the "No security check for macros (Not recommended)" option in the Trust Center. Outlook runs all macros without prompting users. This configuration makes users' computers vulnerable to potentially malicious code and is not recommended. If you disable or do not configure this policy setting, the behavior is the equivalent of Enabled -- Warning for signed, disable unsigned.)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Trust Center "Security setting for macros" is set to "Enabled (Warn for signed, disable unsigned)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value Level is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Trust Center "Security setting for macros" to "Enabled (Warn for signed, disable unsigned)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30697r497714_chk'
  tag severity: 'medium'
  tag gid: 'V-228464'
  tag rid: 'SV-228464r508021_rule'
  tag stig_id: 'DTOO276'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-30682r497715_fix'
  tag 'documentable'
  tag legacy: ['SV-85873', 'V-71249']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
