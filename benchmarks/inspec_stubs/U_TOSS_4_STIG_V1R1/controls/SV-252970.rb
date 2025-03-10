control 'SV-252970' do
  title 'All TOSS local interactive user home directories must be owned by root.'
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', "Check that all user home directories are owned by the root user with the following command:

$ find $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) -maxdepth 0 -not -user root -ls

If there is any output, this is a finding."
  desc 'fix', %q(Change the owner of interactive user's home directories to root. 

To change the owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "smithj."

$ sudo chown root /home/smithj)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56423r824232_chk'
  tag severity: 'medium'
  tag gid: 'V-252970'
  tag rid: 'SV-252970r824234_rule'
  tag stig_id: 'TOSS-04-020310'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-56373r824233_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
