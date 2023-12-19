control 'SV-252955' do
  title 'TOSS must reveal error messages only to authorized users.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log/messages" file has a mode of "0640" or less permissive and is owned by the root user with the following command:

$ sudo ls -l /var/log/messages
-rw-r----- 1 root root 59782947 Jul 20 01:36 /var/log/messages

If the "/var/log/messages" file has a mode more permissive than "0640", this is a finding.
If the "/var/log/messages" file is not owned by "root", this is a finding.

Verify the "/var/log" directory has a mode of "0755" or less permissive and is owned by the root user with the following command:

$ sudo ls -ld /var/log/
drwxr-xr-x 1 root root 1200 Jul 19 03:39 /var/log

If the "/var/log/" directory has a mode more permissive than "0755", this is a finding. 
If the "/var/log/" directory is not owned by "root", this is a finding.'
  desc 'fix', 'Change the permissions of the file "/var/log/messages" to "0640" and the ownership of the file to "root" by running the following commands:

$ sudo chmod 0640 /var/log/messages
$ sudo chown root /var/log/messages

Change the permissions of the directory "/var/log/" to "0755" and the ownership of the directory to "root" by running the following commands:

$ sudo chmod 0755 /var/log/
$ sudo chown root /var/log/'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56408r824187_chk'
  tag severity: 'medium'
  tag gid: 'V-252955'
  tag rid: 'SV-252955r824189_rule'
  tag stig_id: 'TOSS-04-020150'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-56358r824188_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
