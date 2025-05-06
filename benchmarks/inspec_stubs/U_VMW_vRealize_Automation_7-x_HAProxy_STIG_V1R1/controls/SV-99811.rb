control 'SV-99811' do
  title 'HAProxy must use SSL/TLS protocols in order to secure passwords during transmission from the client.'
  desc 'Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Even when data is passed through a load balancer, data used to authenticate users must be sent via SSL/TLS.'
  desc 'check', "At the command line execute the following command:

cat /etc/haproxy/conf.d/20-vcac.cfg | awk '$0 ~ /bind.*:80/ || $0 ~ /redirect.*ssl_fc/ {print}'

If the command does not return the two lines below, this is a finding.

bind 0.0.0.0:80
redirect scheme https if !{ ssl_fc }"
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to and configure the "frontend https-in" section with the following two values:  

bind 0.0.0.0:80
redirect scheme https if !{ ssl_fc }'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89161'
  tag rid: 'SV-99811r1_rule'
  tag stig_id: 'VRAU-HA-000190'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-95903r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
