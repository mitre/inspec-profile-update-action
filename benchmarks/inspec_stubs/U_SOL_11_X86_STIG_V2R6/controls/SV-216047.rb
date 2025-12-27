control 'SV-216047' do
  title 'The operating system must protect audit tools from unauthorized access.'
  desc 'Failure to maintain system configurations may result in privilege escalation.'
  desc 'check', 'The Software Installation Profile is required.

Determine what the signature policy is for pkg publishers:

# pkg property | grep signature-policy

Check that output produces:

signature-policy verify

If the output does not confirm that signature-policy verify is active, this is a finding.

Check that package permissions are configured and signed per vendor requirements.

# pkg verify

If the command produces any output unrelated to STIG changes, this is a finding.

There is currently a Solaris 11 bug 16267888 which reports pkg verify errors for a variety of python packages. These can be ignored.'
  desc 'fix', 'The Software Installation Profile is required.

Configure the package system to ensure that digital signatures are verified.

# pfexec pkg set-property signature-policy verify

Check that package permissions are configured per vendor requirements.

# pfexec pkg verify

If any errors are reported unrelated to STIG changes, use:

# pfexec pkg fix

to bring configuration settings and permissions into factory compliance.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17285r372523_chk'
  tag severity: 'medium'
  tag gid: 'V-216047'
  tag rid: 'SV-216047r603268_rule'
  tag stig_id: 'SOL-11.1-020030'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-17283r372524_fix'
  tag 'documentable'
  tag legacy: ['SV-60757', 'V-47885']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
