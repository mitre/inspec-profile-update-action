control 'SV-239115' do
  title 'The Photon operating system messages file must have mode 0640 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state and can provide sensitive information to an unprivileged attacker."
  desc 'check', 'At the command line, execute the following command:

# stat -c "%n permissions are %a" /var/log/vmware/messages

If the permissions on the file are more permissive than 0640, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

# chmod 0640 /var/log/vmware/messages'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42326r675151_chk'
  tag severity: 'medium'
  tag gid: 'V-239115'
  tag rid: 'SV-239115r675153_rule'
  tag stig_id: 'PHTN-67-000043'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-42285r675152_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
