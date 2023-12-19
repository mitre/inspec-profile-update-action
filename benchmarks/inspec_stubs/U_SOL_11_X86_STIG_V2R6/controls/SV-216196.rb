control 'SV-216196' do
  title 'The system must not allow users to configure .forward files.'
  desc 'Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization. The .forward file also poses a secondary risk as it can be used to execute commands that may perform unintended actions.'
  desc 'check', %q(The root role is required.

# for dir in \
`logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do
ls -l ${dir}/.forward 2>/dev/null
done

If output is produced, this is a finding.)
  desc 'fix', 'The root role is required.

Remove any .forward files that are found.

# pfexec rm [filename]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17434r372970_chk'
  tag severity: 'medium'
  tag gid: 'V-216196'
  tag rid: 'SV-216196r603268_rule'
  tag stig_id: 'SOL-11.1-070170'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17432r372971_fix'
  tag 'documentable'
  tag legacy: ['SV-60937', 'V-48065']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
