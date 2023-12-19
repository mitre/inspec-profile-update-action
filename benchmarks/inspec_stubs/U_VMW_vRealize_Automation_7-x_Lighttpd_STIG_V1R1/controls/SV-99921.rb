control 'SV-99921' do
  title 'Lighttpd must prevent hosted applications from exhausting system resources.'
  desc 'When it comes to DoS attacks, most of the attention is paid to ensuring that systems and applications are not victims of these attacks. While it is true that those accountable for systems want to ensure they are not affected by a DoS attack, they also need to ensure their systems and applications are not used to launch such an attack against others. To that extent, a variety of technologies exist to limit, or in some cases, eliminate the effects of DoS attacks. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks. Applications and application developers must take the steps needed to ensure users cannot use these applications to launch DoS attacks against other systems and networks. 

An example would be preventing Lighttpd from keeping idle connections open for too long.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^server.max-keep-alive-idle' /opt/vmware/etc/lighttpd/lighttpd.conf

If the "server.max-keep-alive-idle" is not set to "30", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Configure the lighttpd.conf file with the following:

server.max-keep-alive-idle = 30'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89271'
  tag rid: 'SV-99921r1_rule'
  tag stig_id: 'VRAU-LI-000210'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-96013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
