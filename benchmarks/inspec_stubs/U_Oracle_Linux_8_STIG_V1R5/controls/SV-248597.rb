control 'SV-248597' do
  title 'There must be no "shosts.equiv" files on the OL 8 operating system.'
  desc 'The "shosts.equiv" files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify there are no "shosts.equiv" files on OL 8 with the following command: 
 
$ sudo find / -name shosts.equiv 
 
If an "shosts.equiv" file is found, this is a finding.'
  desc 'fix', 'Remove any found "shosts.equiv" files from the system. 
 
$ sudo rm /etc/ssh/shosts.equiv'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52031r779355_chk'
  tag severity: 'high'
  tag gid: 'V-248597'
  tag rid: 'SV-248597r779357_rule'
  tag stig_id: 'OL08-00-010460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51985r779356_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
