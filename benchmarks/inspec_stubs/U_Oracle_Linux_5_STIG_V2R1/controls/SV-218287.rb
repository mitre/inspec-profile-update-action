control 'SV-218287' do
  title 'The /etc/nsswitch.conf file must be owned by root.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Verify the /etc/nsswitch.conf file is owned by root.

# ls -l /etc/nsswitch.conf

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/nsswitch.conf file to root.

# chown root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19762r561650_chk'
  tag severity: 'medium'
  tag gid: 'V-218287'
  tag rid: 'SV-218287r603259_rule'
  tag stig_id: 'GEN001371'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19760r561651_fix'
  tag 'documentable'
  tag legacy: ['V-22327', 'SV-64535']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
