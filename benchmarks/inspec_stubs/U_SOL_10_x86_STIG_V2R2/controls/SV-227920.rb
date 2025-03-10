control 'SV-227920' do
  title "The system's NFS export configuration must not have the sec option set to none (or equivalent); additionally, the default authentication must not to be set to none."
  desc 'If sec=none on Solaris, all NFS requests are mapped to an unknown/common user instead of being processed according to the provided UID.'
  desc 'check', 'Perform the following on NFS servers:

# grep "^default" /etc/nfssec.conf

Check to ensure the second column does not equal 0. This would indicate the default is set to none. Perform the following to check currently exported file systems.

# more /etc/dfs/dfstab

If the option sec=none is set on any of the exported file systems, this is a finding.'
  desc 'fix', 'Edit the /etc/dfs/dfstab file and add the sec=XXX option to the share line as an option.  XXX must be a valid option for the system other than none.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30082r490174_chk'
  tag severity: 'medium'
  tag gid: 'V-227920'
  tag rid: 'SV-227920r603266_rule'
  tag stig_id: 'GEN005860'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30070r490175_fix'
  tag 'documentable'
  tag legacy: ['SV-40306', 'V-934']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
