control 'SV-218217' do
  title 'The system must display the date and time of the last successful account login upon login.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Check that pam_lastlog is used and not silent, or that the SSH daemon is configured to display last login information.

# grep pam_lastlog /etc/pam.d/sshd
If pam_lastlog is present, and does not have the "silent" option, this is not a finding.

# grep -i PrintLastLog /etc/ssh/sshd_config

If PrintLastLog is not present in the configuration, this is not a finding. This is the default setting.
If PrintLastLog is present in the configuration and set to "yes" (case insensitive), this is not a finding.
Otherwise, this is a finding.'
  desc 'fix', 'Implement pam_lastlog, or enable PrintLastLog in the SSH daemon.

To enable pam_lastlog, add a line such as "session required pam_lastlog.so" to /etc/pam.d/sshd.

To enable PrintLastLog in the SSH daemon, remove any lines disabling this option from /etc/ssh/sshd_config.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19692r553988_chk'
  tag severity: 'low'
  tag gid: 'V-218217'
  tag rid: 'SV-218217r603259_rule'
  tag stig_id: 'GEN000452'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19690r553989_fix'
  tag 'documentable'
  tag legacy: ['V-22299', 'SV-63373']
  tag cci: ['CCI-000052', 'CCI-000366']
  tag nist: ['AC-9', 'CM-6 b']
end
