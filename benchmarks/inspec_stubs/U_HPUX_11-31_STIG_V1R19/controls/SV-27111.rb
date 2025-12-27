control 'SV-27111' do
  title 'The system must require that passwords contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'check', 'For Trusted Mode:
Check the system password length setting. For Trusted systems, the range of supported values for N is 6 to 80.
# grep MIN_PASSWORD_LENGTH /etc/default/security

If the MIN_PASSWORD_LENGTH attribute (N) is not set to 15 or greater, this is a finding.

For SMSE:
Check the system password length setting. For Standard (non-SMSE enabled) systems, the maximum supported length is  N=8. Once the /etc/shadow file is created and long passwords are enabled (may require additional software product installations), check the system password length setting. The LONG_PASSWORD attribute is valid only when the LongPassword11i3 product is installed and the password hash algorithm is different from the traditional DES-based hash algorithm.
# egrep "CRYPT_ALGORITHMS_DEPRECATE|CRYPT_DEFAULT|LONG_PASSWORD|MIN_PASSWORD_LENGTH" /etc/default/security /var/adm/userdb/*

The following is an example output from the above command:
CRYPT_ALGORITHMS_DEPRECATE=__unix__
CRYPT_DEFAULT=6
LONG_PASSWORD=1
MIN_PASSWORD_LENGTH=15

Note: The MIN_PASSWORD_LENGTH attribute may exceed 15 characters.

If the attributes CRYPT_ALGORITHMS_DEPRECATE, CRYPT_DEFAULT, LONG_PASSWORD, and MIN_PASSWORD_LENGTH are not set per the above example output, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface to set the system password length attribute “MIN_PASSWORD_LENGTH” to 15 or greater.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Install the additional LongPassword11i3 and PHI11i3 product bundles where/as required. Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the attribute(s). See the below example(s):
CRYPT_ALGORITHMS_DEPRECATE=__unix__
CRYPT_DEFAULT=6
LONG_PASSWORD=1
MIN_PASSWORD_LENGTH=15

Note: The MIN_PASSWORD_LENGTH attribute must be set equal to or greater than 15.
If the "vi" editor was used to update the /etc/default/security file, save the file before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-28027r5_chk'
  tag severity: 'medium'
  tag gid: 'V-11947'
  tag rid: 'SV-27111r4_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'GEN000580'
  tag fix_id: 'F-24374r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
