control 'SV-215347' do
  title 'The AIX rlogind service must be disabled.'
  desc 'The rlogin daemon permits username and passwords to be passed over the network in clear text.'
  desc 'check', 'Determine if the "rlogind" service is running by running the following command:
# grep -v "^#" /etc/inetd.conf |grep rlogin 

If the above grep command returned a line that contains "rlogin", this is a finding.'
  desc 'fix', %q(Disable the rlogind service by editing the "'etc/inetd.conf" file. 

# vi /etc/inetd.conf 

Comment out the "rlogind" service. 

Restart the inetd service: 
# refresh -s inetd)
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16545r294492_chk'
  tag severity: 'high'
  tag gid: 'V-215347'
  tag rid: 'SV-215347r508663_rule'
  tag stig_id: 'AIX7-00-003041'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16543r294493_fix'
  tag 'documentable'
  tag legacy: ['V-91301', 'SV-101399']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
