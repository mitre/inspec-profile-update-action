control 'SV-250577' do
  title 'The root accounts list of preloaded libraries must be empty.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with (/) are absolute paths.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep LD_PRELOAD /etc/vmware/config

If the LD_PRELOAD attribute is present and set to anything other than an empty string, this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/vmware/config

Set the LD_PRELOAD to "".

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54012r798728_chk'
  tag severity: 'medium'
  tag gid: 'V-250577'
  tag rid: 'SV-250577r798730_rule'
  tag stig_id: 'GEN000950-ESXI5-444'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53966r798729_fix'
  tag 'documentable'
  tag legacy: ['V-39383', 'SV-51241']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
