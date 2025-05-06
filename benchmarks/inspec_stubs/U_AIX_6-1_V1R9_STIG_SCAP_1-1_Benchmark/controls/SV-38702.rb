control 'SV-38702' do
  title 'The system must provide protection against IP fragmentation attacks.'
  desc 'The parameter ip_nfrag provides an additional layer of protection against IP fragmentation attacks.  The value the ip_nfrag specifies is the maximum number of fragments of an IP packet that can be kept in the IP reassembly queue at any time. The default value of this network option is 200.  This is a reasonable value for most environments and offers protection from IP fragmentation attacks.'
  desc 'fix', 'Set the ip_nfrag parameter to 200.

# /usr/sbin/no -p -o ip_nfrag=200'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29498'
  tag rid: 'SV-38702r1_rule'
  tag stig_id: 'GEN000000-AIX0230'
  tag gtitle: 'GEN000000-AIX0230'
  tag fix_id: 'F-33056r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
