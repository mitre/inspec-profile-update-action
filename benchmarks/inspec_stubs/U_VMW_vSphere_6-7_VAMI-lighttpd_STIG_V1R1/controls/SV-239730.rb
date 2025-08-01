control 'SV-239730' do
  title 'VAMI must prevent hosted applications from exhausting system resources.'
  desc 'Most of the attention to denial-of-service (DoS) attacks focuses on ensuring that systems and applications are not victims of these attacks. However, these systems and applications must also be secured against use to launch such an attack against others. 

A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks. 

One DoS mitigation is to prevent VAMI from keeping idle connections open for too long.'
  desc 'check', 'At the command prompt, execute the following command:

# /opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf|grep "server.max-keep-alive-idle"

Expected result:

    server.max-keep-alive-idle        = 30

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file.

Add or reconfigure the following value:

server.max-keep-alive-idle = 30'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 VAMI-lighttpd'
  tag check_id: 'C-42963r679298_chk'
  tag severity: 'medium'
  tag gid: 'V-239730'
  tag rid: 'SV-239730r679300_rule'
  tag stig_id: 'VCLD-67-000022'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-42922r679299_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
