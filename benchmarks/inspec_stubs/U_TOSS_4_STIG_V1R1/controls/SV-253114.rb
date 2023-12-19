control 'SV-253114' do
  title 'TOSS must enable hardening for the Berkeley Packet Filter Just-in-time compiler.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
Enabling hardening for the Berkeley Packet Filter (BPF) Just-in-time (JIT) compiler aids in mitigating JIT spraying attacks. Setting the value to "2" enables JIT hardening for all users.'
  desc 'check', 'Verify TOSS enables hardening for the BPF JIT with the following commands:

$ sudo sysctl net.core.bpf_jit_harden

net.core.bpf_jit_harden = 2

If the returned line does not have a value of "2", or a line is not returned, this is a finding.'
  desc 'fix', 'Configure TOSS to enable hardening for the BPF JIT compiler by adding the following line to a file in the "/etc/sysctl.d" directory:

net.core.bpf_jit_harden = 2

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56567r825012_chk'
  tag severity: 'medium'
  tag gid: 'V-253114'
  tag rid: 'SV-253114r825014_rule'
  tag stig_id: 'TOSS-04-040730'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56517r825013_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
