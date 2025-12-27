control 'SV-215269' do
  title 'The inetd.conf file on AIX must be owned by root and system group.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', %q(Check the ownership of "/etc/inetd.conf": 
# ls -l /etc/inetd.conf | awk '{print $1 " " $3 " " $4 " " $9}'

The above command should yield the following output:
-rw-r--r-- root system /etc/inetd.conf

If it does not, this is a finding.)
  desc 'fix', 'Change the "mode-bit" and the ownership of "/etc/inetd.conf": 
# chmod 644 /etc/inetd.conf 
# chown root:system /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16467r294258_chk'
  tag severity: 'medium'
  tag gid: 'V-215269'
  tag rid: 'SV-215269r508663_rule'
  tag stig_id: 'AIX7-00-002077'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16465r294259_fix'
  tag 'documentable'
  tag legacy: ['V-91587', 'SV-101685']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
