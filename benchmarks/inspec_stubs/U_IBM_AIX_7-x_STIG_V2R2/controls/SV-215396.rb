control 'SV-215396' do
  title 'AIX process core dumps must be disabled.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', 'From the command prompt, run the following command:

# lsuser -a core ALL 
root core=0
daemon core=0
bin core=0
sys core=0
adm core=0
uucp core=0
snapp core=0
ipsec core=0
srvproxy core=0
esaadmin core=0
sshd core=0
doejohn core=0

If any user does not have a value of "core = 0", this is a finding.'
  desc 'fix', 'Run command:
# chsec -f /etc/security/limits -s default -a core=0'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16594r294639_chk'
  tag severity: 'medium'
  tag gid: 'V-215396'
  tag rid: 'SV-215396r508663_rule'
  tag stig_id: 'AIX7-00-003093'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16592r294640_fix'
  tag 'documentable'
  tag legacy: ['SV-101771', 'V-91673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
