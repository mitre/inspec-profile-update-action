control 'SV-38323' do
  title 'The /etc/passwd file must not contain password hashes.'
  desc 'If password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', 'Verify no password hashes are present in /etc/passwd.
# cat /etc/passwd | cut -f 2,2 -d “:” 

If any password hashes are returned, this is a finding.'
  desc 'fix', 'Migrate /etc/passwd password hashes. 

For Trusted Mode:
Use the System Administration Manager (SAM) or the System Management Homepage (SMH) to migrate from a non-SMSE Standard Mode to Trusted Mode.

For SMSE Mode:
Use the following command to create the shadow file. The command will then copy all encrypted passwords into the shadow file and replace the passwd file password entries with an “x”.
# pwconv'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36358r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22347'
  tag rid: 'SV-38323r2_rule'
  tag stig_id: 'GEN001470'
  tag gtitle: 'GEN001470'
  tag fix_id: 'F-31694r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000201']
  tag nist: ['IA-5 (6)']
end
