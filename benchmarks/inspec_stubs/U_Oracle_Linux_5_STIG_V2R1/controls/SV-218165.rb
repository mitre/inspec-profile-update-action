control 'SV-218165' do
  title 'The /etc/gshadow file must have mode 0400.'
  desc 'The /etc/gshadow file is critical to system security and must be protected from unauthorized modification.   The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'check', 'Check the mode of the /etc/gshadow file.
# ls -l /etc/gshadow
If the file mode is more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/gshadow file to 0400 or less permissive.
# chmod 0400 /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19640r561455_chk'
  tag severity: 'medium'
  tag gid: 'V-218165'
  tag rid: 'SV-218165r603259_rule'
  tag stig_id: 'GEN000000-LNX001433'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19638r561456_fix'
  tag 'documentable'
  tag legacy: ['V-22343', 'SV-62697']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
