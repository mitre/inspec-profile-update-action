control 'SV-256516' do
  title 'The Photon operating system messages file must have the correct ownership and file permissions.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state and can provide sensitive information to an unprivileged attacker."
  desc 'check', 'At the command line, run the following command:

# stat -c "%n is owned by %U and group owned by %G with %a permissions" /var/log/messages

If the "/var/log/messages" directory is not owned by root or not group owned by root, or the file permissions are more permission than "640", this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# chown root:root /var/log/messages

# chmod 0640 /var/log/messages'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60191r887220_chk'
  tag severity: 'medium'
  tag gid: 'V-256516'
  tag rid: 'SV-256516r887222_rule'
  tag stig_id: 'PHTN-30-000041'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-60134r887221_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
