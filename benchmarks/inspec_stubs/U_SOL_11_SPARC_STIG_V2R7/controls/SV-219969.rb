control 'SV-219969' do
  title 'The system must verify that package updates are digitally signed.'
  desc 'Digitally signed packages ensure that the source of the package can be identified.'
  desc 'check', 'Determine what the signature policy is for pkg publishers:

# pkg property | grep signature-policy

Check that output produces:

signature-policy verify

If the output does not confirm that signature-policy verify is active, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

Configure the package system to ensure that digital signatures are verified.

# pfexec pkg set-property signature-policy verify'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21679r370931_chk'
  tag severity: 'medium'
  tag gid: 'V-219969'
  tag rid: 'SV-219969r854532_rule'
  tag stig_id: 'SOL-11.1-020020'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-21678r370932_fix'
  tag 'documentable'
  tag legacy: ['V-47883', 'SV-60755']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
