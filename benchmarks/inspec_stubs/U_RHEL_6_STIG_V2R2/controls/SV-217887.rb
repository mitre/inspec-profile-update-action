control 'SV-217887' do
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19368r462370_chk'
  tag severity: 'medium'
  tag gid: 'V-217887'
  tag rid: 'SV-217887r603264_rule'
  tag stig_id: 'RHEL-06-000050'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-19366r462371_fix'
  tag 'documentable'
  tag legacy: ['V-38475', 'SV-50275']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
