control 'SV-99849' do
  title 'HAProxy psql-local frontend must be bound to port 5433.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The HAProxy load balancer in the vRA appliance listens to port 5433 on behalf of the PostgreSQL service.'
  desc 'check', "At the command prompt, execute the following command:
 
grep 'bind' /etc/haproxy/conf.d/10-psql.cfg
 
If the value for bind is not set to 5433, this is a finding."
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/10-psql.cfg

Navigate to and configure the "frontend psql-local" section with the following value:  

bind 127.0.0.1:5433'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89199'
  tag rid: 'SV-99849r1_rule'
  tag stig_id: 'VRAU-HA-000395'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-95941r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
