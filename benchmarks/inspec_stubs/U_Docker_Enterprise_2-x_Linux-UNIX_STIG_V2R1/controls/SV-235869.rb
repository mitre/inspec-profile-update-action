control 'SV-235869' do
  title 'Docker Enterprise /etc/default/docker file ownership must be set to root:root.'
  desc 'Verify that the /etc/default/docker file ownership and group-ownership is correctly set to root.

/etc/default/docker file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be owned and group-owned by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable.'
  desc 'check', 'This requirement applies to Ubuntu Linux systems only. 

Ensure that /etc/default/docker file ownership is set to root:root.

Execute the below command to verify that the file is owned and group-owned by root:

stat -c %U:%G /etc/default/docker 

If file ownership it not set to root:root, this is a finding.'
  desc 'fix', 'Set the ownership and group-ownership for the file to root.

Run the following command:
chown root:root /etc/default/docker'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39088r627732_chk'
  tag severity: 'high'
  tag gid: 'V-235869'
  tag rid: 'SV-235869r627734_rule'
  tag stig_id: 'DKER-EE-005350'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39051r627733_fix'
  tag 'documentable'
  tag legacy: ['SV-104913', 'V-95775']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
