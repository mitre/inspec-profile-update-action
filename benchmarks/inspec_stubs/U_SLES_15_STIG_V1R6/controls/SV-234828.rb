control 'SV-234828' do
  title 'The sticky bit must be set on all SUSE operating system world-writable directories.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, and hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Verify the SUSE operating system prevents unauthorized and unintended information transfer via the shared system resources.

Check that world-writable directories have the sticky bit set with the following command:

> sudo find / \\( -path /.snapshots -o -path /sys -o -path /proc \\) -prune -o -perm -002 -type d -exec ls -lLd {} \\;

256 0 drwxrwxrwt 1 root root 4096 Jun 14 06:45 /tmp

If any of the returned directories do not have the sticky bit set, or are not documented as having the write permission for the other class, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system shared system resources to prevent any unauthorized and unintended information transfer by setting the sticky bit for all world-writable directories.

An example of a world-writable directory is "/tmp" directory. Set the sticky bit on all of the world-writable directories (using the "/tmp" directory as an example) with the following command:

> sudo chmod 1777 /tmp

For every world-writable directory, replace "/tmp" in the command above with the world-writable directory that does not have the sticky bit set.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38016r618753_chk'
  tag severity: 'medium'
  tag gid: 'V-234828'
  tag rid: 'SV-234828r622137_rule'
  tag stig_id: 'SLES-15-010300'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-37979r618754_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
