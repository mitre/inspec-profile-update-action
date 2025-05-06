control 'SV-239727' do
  title 'VAMI must remove all mappings to unused scripts.'
  desc 'Scripts allow server-side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. To ensure scripts are not added to the web server and run maliciously, script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf|awk '/cgi\.assign/,/\\)/'

Expected result:

    cgi.assign                        = (
        ".pl"  => "/usr/bin/perl",
        ".cgi" => "/usr/bin/perl",
        ".rb"  => "/usr/bin/ruby",
        ".erb" => "/usr/bin/eruby",
        ".py"  => "/usr/bin/python",
        # 5
    )

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the "cgi.assign" section to the following:

    cgi.assign                        = (
        ".pl"  => "/usr/bin/perl",
        ".cgi" => "/usr/bin/perl",
        ".rb"  => "/usr/bin/ruby",
        ".erb" => "/usr/bin/eruby",
        ".py"  => "/usr/bin/python",
        # 5
    )'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 VAMI-lighttpd'
  tag check_id: 'C-42960r679289_chk'
  tag severity: 'medium'
  tag gid: 'V-239727'
  tag rid: 'SV-239727r679291_rule'
  tag stig_id: 'VCLD-67-000019'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-42919r679290_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
