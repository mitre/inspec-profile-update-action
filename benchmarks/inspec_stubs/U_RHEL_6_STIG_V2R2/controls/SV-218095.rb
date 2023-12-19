control 'SV-218095' do
  title 'The NFS server must not have the all_squash option enabled.'
  desc 'The "all_squash" option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID.'
  desc 'check', 'If the NFS server is read-only, in support of unrestricted access to organizational content, this is not applicable.

The related "root_squash" option provides protection against remote administrator-level access to NFS server content.  Its use is not a finding.

To verify the "all_squash" option has been disabled, run the following command:

# grep all_squash /etc/exports


If there is output, this is a finding.'
  desc 'fix', 'Remove any instances of the "all_squash" option from the file "/etc/exports".  Restart the NFS daemon for the changes to take effect.

# service nfs restart'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19576r377300_chk'
  tag severity: 'low'
  tag gid: 'V-218095'
  tag rid: 'SV-218095r603264_rule'
  tag stig_id: 'RHEL-06-000515'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-19574r377301_fix'
  tag 'documentable'
  tag legacy: ['SV-50260', 'V-38460']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
