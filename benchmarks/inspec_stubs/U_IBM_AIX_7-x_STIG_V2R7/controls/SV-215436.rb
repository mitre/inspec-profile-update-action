control 'SV-215436' do
  title 'The AIX operating system must use Multi Factor Authentication.'
  desc 'To assure accountability and prevent unauthenticated access, privileged and non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
1. Something you know (e.g., password/PIN);
2. Something you have (e.g., cryptographic identification device, token); and
3. Something you are (e.g., biometric).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.


'
  desc 'check', 'Verify that all required packages are installed:

# lslpp -l |grep -i powerscmfa

  powerscMFA.license        1.2.0.1  COMMITTED  PowerSC MFA license files
  powerscMFA.pam.base        1.2.0.1 COMMITTED  PowerSC MFA standard inband
  powerscMFA.pam.fallback    1.2.0.1 COMMITTED  PowerSC MFA Password fallback
  powerscMFA.pam.pmfamapper  1.2.0.1  COMMITTED USB Smartcard Interface to
  powerscMFA.pam.usbsmartcard

If any of the above packages are not installed, this is a finding.'
  desc 'fix', 'Install the IBM PowerSC MFA product.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16634r294759_chk'
  tag severity: 'medium'
  tag gid: 'V-215436'
  tag rid: 'SV-215436r853492_rule'
  tag stig_id: 'AIX7-00-003200'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-16632r294760_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000375-GPOS-00160']
  tag 'documentable'
  tag legacy: ['V-92941', 'SV-103029']
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-001948']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (11)']
end
