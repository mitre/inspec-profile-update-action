control 'SV-239113' do
  title 'The Photon operating system /var/log directory must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state and can provide sensitive information to an unprivileged attacker."
  desc 'check', 'At the command line, execute the following command:

# stat -c "%n is owned by %U and group owned by %G" /var/log 

If the /var/log is not owned by root, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

# chown root:root /var/log'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42324r675145_chk'
  tag severity: 'medium'
  tag gid: 'V-239113'
  tag rid: 'SV-239113r675147_rule'
  tag stig_id: 'PHTN-67-000041'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-42283r675146_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
