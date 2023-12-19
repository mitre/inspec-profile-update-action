control 'SV-99825' do
  title 'HAProxy must limit the amount of time that half-open connections are kept alive.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is to limit the amount of time that a half-open connection is kept alive.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'timeout client-fin' /etc/haproxy/haproxy.cfg

If the return value for "timeout client-fin" list is not set to "30s", this is a finding.)
  desc 'fix', "Navigate to and open /etc/haproxy/haproxy.cfg   

Configure the haproxy.cfg file with the following value in the defaults section: 

'timeout client-fin 30s'."
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89175'
  tag rid: 'SV-99825r1_rule'
  tag stig_id: 'VRAU-HA-000300'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-95917r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
