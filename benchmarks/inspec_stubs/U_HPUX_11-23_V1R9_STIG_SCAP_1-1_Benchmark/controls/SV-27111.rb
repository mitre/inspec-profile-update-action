control 'SV-27111' do
  title 'The system must require that passwords contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
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
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-11947'
  tag rid: 'SV-27111r4_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'GEN000580'
  tag fix_id: 'F-24374r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
