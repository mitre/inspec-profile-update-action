control 'SV-208867' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'Disabling SCTP protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'If the system is configured to prevent the loading of the "sctp" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r sctp /etc/modprobe.conf /etc/modprobe.d | grep -i “/bin/true”

If no line is returned, this is a finding.'
  desc 'fix', 'The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. To configure the system to prevent the "sctp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install sctp /bin/true'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9120r357581_chk'
  tag severity: 'medium'
  tag gid: 'V-208867'
  tag rid: 'SV-208867r603263_rule'
  tag stig_id: 'OL6-00-000125'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9120r357582_fix'
  tag 'documentable'
  tag legacy: ['V-50997', 'SV-65203']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
