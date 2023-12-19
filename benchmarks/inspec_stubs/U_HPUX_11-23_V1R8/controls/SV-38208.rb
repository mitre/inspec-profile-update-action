control 'SV-38208' do
  title 'The root shell must be located in the / file system.'
  desc 'To ensure the root shell is available in repair and administrative modes, the root shell must be located in the / file system.'
  desc 'check', %q(Determine if the root shell is located on / (IE: a non-mounted file system).
# cat /etc/passwd  | grep "^root:" | awk -F ":" '{print $NF}'
# grep <shell location from above> /etc/fstab

If the root shell is located on a mountable file system listed in /etc/fstab, this is a finding.)
  desc 'fix', "Change the root account's shell to one present on the / file system."
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36281r1_chk'
  tag severity: 'low'
  tag gid: 'V-1062'
  tag rid: 'SV-38208r1_rule'
  tag stig_id: 'GEN001080'
  tag gtitle: 'GEN001080'
  tag fix_id: 'F-31538r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
