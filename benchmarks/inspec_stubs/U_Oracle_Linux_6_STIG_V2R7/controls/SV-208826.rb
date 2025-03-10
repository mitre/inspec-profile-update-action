control 'SV-208826' do
  title 'The system must require passwords to contain a minimum of 15 characters.'
  desc 'Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result.

While it does not negate the password length requirement, it is preferable to migrate from a password-based authentication scheme to a stronger one based on PKI (public key infrastructure).'
  desc 'check', 'To check the minimum password length, run the command: 

$ grep PASS_MIN_LEN /etc/login.defs

The DoD requirement is "15". 

If it is not set to the required value, this is a finding.

$ grep –E ‘pam_cracklib.so.*minlen’ /etc/pam.d/*

If no results are returned, this is not a finding.

If any results are returned and are not set to “15” or greater, this is a finding.'
  desc 'fix', 'To specify password length requirements for new accounts, edit the file "/etc/login.defs" and add or correct the following lines: 

PASS_MIN_LEN 15

The DoD requirement is "15". If a program consults "/etc/login.defs" and also another PAM module (such as "pam_cracklib") during a password change operation, then the most restrictive must be satisfied.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9079r357458_chk'
  tag severity: 'medium'
  tag gid: 'V-208826'
  tag rid: 'SV-208826r793611_rule'
  tag stig_id: 'OL6-00-000050'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-9079r357459_fix'
  tag 'documentable'
  tag legacy: ['V-50791', 'SV-64997']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
