control 'SV-239523' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security. Unauthorized modification of these files could compromise these processes and SLES for vRealize."
  desc 'check', %q(Perform the following to check NIS file ownership:

# ls -la /var/yp/*

If the NIS file's mode is more permissive than "0755", this is a finding.)
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to "0755" or less permissive:

# chmod 0755 <filename>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42756r662018_chk'
  tag severity: 'medium'
  tag gid: 'V-239523'
  tag rid: 'SV-239523r662020_rule'
  tag stig_id: 'VROM-SL-000520'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42715r662019_fix'
  tag 'documentable'
  tag legacy: ['SV-99167', 'V-88517']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
