control 'SV-216432' do
  title 'User .netrc files must not exist.'
  desc 'The .netrc file presents a significant security risk since it stores passwords in unencrypted form.'
  desc 'check', %q(The root role is required.

Check for the presence of user .netrc files.

# for dir in \
`logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do
ls -l ${dir}/.netrc 2>/dev/null
done

If output is produced, this is a finding.)
  desc 'fix', 'The root role is required.

Determine if any .netrc files exist, and work with the owners to determine the best course of action in accordance with site policy.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17668r371384_chk'
  tag severity: 'medium'
  tag gid: 'V-216432'
  tag rid: 'SV-216432r603267_rule'
  tag stig_id: 'SOL-11.1-070160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17666r371385_fix'
  tag 'documentable'
  tag legacy: ['SV-60939', 'V-48067']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
