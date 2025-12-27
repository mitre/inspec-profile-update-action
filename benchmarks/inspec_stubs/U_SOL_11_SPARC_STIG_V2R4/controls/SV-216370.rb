control 'SV-216370' do
  title 'The system must not respond to ICMP broadcast timestamp requests.'
  desc "By accurately determining the system's clock state, an attacker can more effectively attack certain time-based pseudorandom number generators (PRNGs) and the authentication systems that rely on them."
  desc 'check', 'Determine if response to ICMP broadcast timestamp requests is disabled.

# ipadm show-prop -p _respond_to_timestamp_broadcast -co current ip

If the output of this command is not "0", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable respond to timestamp broadcasts.

# pfexec ipadm set-prop -p _respond_to_timestamp_broadcast=0 ip'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17606r371198_chk'
  tag severity: 'low'
  tag gid: 'V-216370'
  tag rid: 'SV-216370r603267_rule'
  tag stig_id: 'SOL-11.1-050030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17604r371199_fix'
  tag 'documentable'
  tag legacy: ['SV-61045', 'V-48173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
